/**
 * Strongly typed environment handling.
 *
 * Cloudflare Workers have no traditional "process start", so validation runs
 * once per isolate on the first request (memoised per env object). A
 * misconfigured deployment fails loudly with a 500 and a structured log line
 * that names the offending variables — never their values.
 */

/** Raw bindings exactly as Cloudflare delivers them (vars + secrets are strings). */
export interface Bindings {
  readonly UPSTASH_REDIS_REST_URL?: string;
  readonly UPSTASH_REDIS_REST_TOKEN?: string;
  readonly ADMIN_API_TOKEN?: string;
  readonly REDIS_TIMEOUT_MS?: string;
  readonly KEY_CACHE_TTL_SECONDS?: string;
  readonly LOG_DRAIN_URL?: string;
  readonly LOG_DRAIN_TOKEN?: string;
  readonly ENVIRONMENT?: string;
}

export type DeploymentEnvironment = 'production' | 'staging' | 'development';

/** Validated, normalised configuration. Every field is guaranteed present and sane. */
export interface Config {
  readonly redisUrl: string;
  readonly redisToken: string;
  readonly adminToken: string | null;
  readonly redisTimeoutMs: number;
  readonly keyCacheTtlMs: number;
  readonly logDrainUrl: string | null;
  readonly logDrainToken: string | null;
  readonly environment: DeploymentEnvironment;
}

export class ConfigError extends Error {
  /** Names of invalid variables plus the rule they broke. Never contains values. */
  readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super(`Invalid worker configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
    this.issues = issues;
  }
}

const DEFAULT_REDIS_TIMEOUT_MS = 250;
const DEFAULT_KEY_CACHE_TTL_SECONDS = 30;
const MIN_ADMIN_TOKEN_LENGTH = 32;
const LOCAL_HOSTNAMES: ReadonlySet<string> = new Set(['localhost', '127.0.0.1', '[::1]']);

function readTrimmed(value: string | undefined): string | null {
  if (value === undefined) {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
}

function parseIntegerInRange(
  name: string,
  raw: string | null,
  fallback: number,
  min: number,
  max: number,
  issues: string[],
): number {
  if (raw === null) {
    return fallback;
  }
  if (!/^\d+$/.test(raw)) {
    issues.push(`${name} must be a non-negative integer`);
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    issues.push(`${name} must be between ${min} and ${max}`);
    return fallback;
  }
  return parsed;
}

function parseEnvironment(raw: string | null, issues: string[]): DeploymentEnvironment {
  if (raw === null) {
    return 'production';
  }
  if (raw === 'production' || raw === 'staging' || raw === 'development') {
    return raw;
  }
  issues.push('ENVIRONMENT must be one of production, staging, development');
  return 'production';
}

function parseServiceUrl(
  name: string,
  raw: string,
  environment: DeploymentEnvironment,
  issues: string[],
): string | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    issues.push(`${name} must be an absolute URL`);
    return null;
  }
  const isLocal = LOCAL_HOSTNAMES.has(url.hostname);
  const plaintextAllowed = environment === 'development' && isLocal;
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && plaintextAllowed)) {
    issues.push(`${name} must use https (http is only accepted for localhost when ENVIRONMENT=development)`);
    return null;
  }
  if (url.username !== '' || url.password !== '') {
    issues.push(`${name} must not embed credentials`);
    return null;
  }
  if (url.search !== '' || url.hash !== '') {
    issues.push(`${name} must not contain a query string or fragment`);
    return null;
  }
  return url.toString().replace(/\/+$/, '');
}

export function parseConfig(env: Bindings): Config {
  const issues: string[] = [];
  const environment = parseEnvironment(readTrimmed(env.ENVIRONMENT), issues);

  const rawRedisUrl = readTrimmed(env.UPSTASH_REDIS_REST_URL);
  let redisUrl: string | null = null;
  if (rawRedisUrl === null) {
    issues.push('UPSTASH_REDIS_REST_URL is required');
  } else {
    redisUrl = parseServiceUrl('UPSTASH_REDIS_REST_URL', rawRedisUrl, environment, issues);
  }

  const redisToken = readTrimmed(env.UPSTASH_REDIS_REST_TOKEN);
  if (redisToken === null) {
    issues.push('UPSTASH_REDIS_REST_TOKEN is required');
  } else if (/\s/.test(redisToken)) {
    issues.push('UPSTASH_REDIS_REST_TOKEN must not contain whitespace');
  }

  const adminToken = readTrimmed(env.ADMIN_API_TOKEN);
  if (adminToken !== null && adminToken.length < MIN_ADMIN_TOKEN_LENGTH) {
    issues.push(`ADMIN_API_TOKEN must be at least ${MIN_ADMIN_TOKEN_LENGTH} characters`);
  }

  const redisTimeoutMs = parseIntegerInRange(
    'REDIS_TIMEOUT_MS',
    readTrimmed(env.REDIS_TIMEOUT_MS),
    DEFAULT_REDIS_TIMEOUT_MS,
    10,
    5_000,
    issues,
  );

  const keyCacheTtlSeconds = parseIntegerInRange(
    'KEY_CACHE_TTL_SECONDS',
    readTrimmed(env.KEY_CACHE_TTL_SECONDS),
    DEFAULT_KEY_CACHE_TTL_SECONDS,
    0,
    300,
    issues,
  );

  const rawDrainUrl = readTrimmed(env.LOG_DRAIN_URL);
  const logDrainUrl =
    rawDrainUrl === null ? null : parseServiceUrl('LOG_DRAIN_URL', rawDrainUrl, environment, issues);
  const logDrainToken = readTrimmed(env.LOG_DRAIN_TOKEN);
  if (logDrainToken !== null && rawDrainUrl === null) {
    issues.push('LOG_DRAIN_TOKEN is set but LOG_DRAIN_URL is missing');
  }

  if (issues.length > 0 || redisUrl === null || redisToken === null) {
    throw new ConfigError(issues.length > 0 ? issues : ['configuration incomplete']);
  }

  return Object.freeze({
    redisUrl,
    redisToken,
    adminToken: adminToken !== null && adminToken.length >= MIN_ADMIN_TOKEN_LENGTH ? adminToken : null,
    redisTimeoutMs,
    keyCacheTtlMs: keyCacheTtlSeconds * 1_000,
    logDrainUrl,
    logDrainToken,
    environment,
  });
}

const configCache = new WeakMap<object, Config | ConfigError>();

/**
 * Validates once per isolate per env object. Errors are memoised too so a
 * broken deployment does not re-run validation on every request.
 */
export function getConfig(env: Bindings): Config {
  const cached = configCache.get(env);
  if (cached instanceof ConfigError) {
    throw cached;
  }
  if (cached !== undefined) {
    return cached;
  }
  try {
    const config = parseConfig(env);
    configCache.set(env, config);
    return config;
  } catch (error: unknown) {
    if (error instanceof ConfigError) {
      configCache.set(env, error);
    }
    throw error;
  }
}
