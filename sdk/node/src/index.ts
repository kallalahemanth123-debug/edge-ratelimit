/**
 * @edge-ratelimit/sdk — Node.js / TypeScript client.
 *
 * Zero runtime dependencies; uses the platform `fetch`, so it runs on
 * Node >= 18.17, Bun, Deno and edge runtimes.
 *
 *   const limiter = new RateLimiter(process.env.RATELIMIT_API_KEY!, { baseUrl: 'https://rl.example.com' });
 *   const { success } = await limiter.check(userId, 10, 60, { action: 'llm_generation', ip });
 */

export const SDK_VERSION = '1.0.0';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface RateLimitResponse {
  /** Whether the caller should let the request proceed. */
  readonly success: boolean;
  /** Limit of the most constrained bucket. */
  readonly limit: number;
  /** Requests left in the most constrained bucket (not authoritative when reason === 'fail_open'). */
  readonly remaining: number;
  /** Unix timestamp (ms) when capacity returns (blocked) or the window rolls over (allowed). */
  readonly reset: number;
  /** True when the subject is currently rate limited. */
  readonly isBlocked: boolean;
  /** 'rate_limited' | 'ip_rate_limited' | 'fail_open' — absent on a normal allow. */
  readonly reason?: string;
}

export interface CheckOptions {
  /** Logical operation being limited, e.g. 'login_attempt'. Defaults to the limiter's defaultAction. */
  readonly action?: string;
  /** End-user IP. Enables a second, per-IP bucket (IPv6 is limited per /64). */
  readonly ip?: string;
  /** Limit for the per-IP bucket. Defaults to `limit`. Requires `ip`. */
  readonly ipLimit?: number;
  /** Abort the check (e.g. when the inbound request is cancelled). Never fails open. */
  readonly signal?: AbortSignal;
}

export interface FailOpenEvent {
  readonly error: unknown;
  readonly attempts: number;
  readonly action: string;
}

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface RateLimiterOptions {
  /** Edge API base URL. Falls back to the RATELIMIT_API_URL environment variable. */
  readonly baseUrl?: string;
  /** Per-attempt timeout. Default 1000 ms. */
  readonly timeoutMs?: number;
  /** Retries on 5xx / network errors / timeouts. Default 2, maximum 2. */
  readonly maxRetries?: number;
  /** Base delay for exponential backoff. Default 100 ms. */
  readonly backoffBaseMs?: number;
  /** Backoff ceiling. Default 1000 ms. */
  readonly backoffMaxMs?: number;
  /** Allow requests when the edge API is unreachable. Default true. */
  readonly failOpen?: boolean;
  /** Remember active blocks in-process so blocked callers never leave the host. Default true. */
  readonly localBlockCache?: boolean;
  /** Bound on locally cached blocks. Default 10 000. */
  readonly localBlockCacheMaxEntries?: number;
  /** Action used when check() is called without one. Default 'default'. */
  readonly defaultAction?: string;
  /** Custom fetch (testing, proxies, instrumentation). */
  readonly fetch?: FetchLike;
  /** Observability hook invoked whenever a check fails open. Must not throw. */
  readonly onFailOpen?: (event: FailOpenEvent) => void;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class RateLimiterError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** Invalid constructor configuration (bad key format, missing base URL, ...). */
export class RateLimiterConfigError extends RateLimiterError {}

/** Invalid arguments to check(). Thrown before any network I/O. */
export class RateLimiterValidationError extends RateLimiterError {}

/** Non-retryable HTTP error from the edge API (400, 401, 403, 413, 415). */
export class RateLimiterHttpError extends RateLimiterError {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;

  constructor(status: number, code: string, message: string, requestId: string | null) {
    super(`${message} (HTTP ${status}, ${code})`);
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

/** Every attempt failed and failOpen is disabled. */
export class RateLimiterUnavailableError extends RateLimiterError {
  readonly attempts: number;

  constructor(attempts: number, cause: unknown) {
    super(`Rate limit service unavailable after ${attempts} attempt(s)`, { cause });
    this.attempts = attempts;
  }
}

// ---------------------------------------------------------------------------
// Constants & validation (mirrors the edge API's rules exactly)
// ---------------------------------------------------------------------------

const API_KEY_PATTERN = /^rlk_[A-Za-z0-9_-]{43}[0-9a-f]{8}$/;
const ACTION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/;
const IDENTIFIER_MAX_LENGTH = 256;
const LIMIT_MAX = 1_000_000;
const WINDOW_MAX_SECONDS = 2_592_000;
const IP_MAX_LENGTH = 64;
const MAX_RETRIES_CAP = 2;
const NON_RETRYABLE_4XX: ReadonlySet<number> = new Set([400, 401, 403, 404, 405, 413, 415, 422]);

function assertInteger(name: string, value: number, min: number, max: number): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new RateLimiterValidationError(`${name} must be an integer between ${min} and ${max}`);
  }
}

function readEnv(name: string): string | undefined {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  const value = env?.[name];
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

function monotonicNow(): number {
  return typeof performance !== 'undefined' && typeof performance.now === 'function' ? performance.now() : Date.now();
}

/** Re-reads `aborted` each call (it changes asynchronously; avoids stale narrowing). */
function isAborted(signal: AbortSignal | undefined): boolean {
  return signal !== undefined && signal.aborted;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/** Runtime guard: the SDK never trusts the wire format blindly. */
export function isRateLimitResponse(value: unknown): value is RateLimitResponse {
  if (!isRecord(value)) {
    return false;
  }
  return (
    typeof value['success'] === 'boolean' &&
    isNonNegativeInteger(value['limit']) &&
    isNonNegativeInteger(value['remaining']) &&
    isNonNegativeInteger(value['reset']) &&
    typeof value['isBlocked'] === 'boolean' &&
    (value['reason'] === undefined || typeof value['reason'] === 'string')
  );
}

function toResponse(value: RateLimitResponse): RateLimitResponse {
  const base = {
    success: value.success,
    limit: value.limit,
    remaining: value.remaining,
    reset: value.reset,
    isBlocked: value.isBlocked,
  };
  return value.reason === undefined ? base : { ...base, reason: value.reason };
}

// ---------------------------------------------------------------------------
// Local block cache (thundering-herd shield on the client side)
// ---------------------------------------------------------------------------

class LocalBlockCache {
  private readonly entries = new Map<string, { response: RateLimitResponse; expiresAt: number }>();
  private readonly maxEntries: number;

  constructor(maxEntries: number) {
    this.maxEntries = maxEntries;
  }

  get(key: string): RateLimitResponse | undefined {
    const entry = this.entries.get(key);
    if (entry === undefined) {
      return undefined;
    }
    if (entry.expiresAt <= monotonicNow()) {
      this.entries.delete(key);
      return undefined;
    }
    return entry.response;
  }

  /** ttlMs is a duration, applied to a monotonic clock: immune to wall-clock jumps. */
  set(key: string, response: RateLimitResponse, ttlMs: number): void {
    if (!(ttlMs > 0)) {
      return;
    }
    this.entries.delete(key);
    this.entries.set(key, { response, expiresAt: monotonicNow() + ttlMs });
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done === true) {
        break;
      }
      this.entries.delete(oldest.value);
    }
  }

  clear(): void {
    this.entries.clear();
  }
}

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

type Attempt =
  | { readonly kind: 'decision'; readonly response: RateLimitResponse; readonly resetAfterMs: number | null }
  | { readonly kind: 'retryable'; readonly error: unknown }
  | { readonly kind: 'fatal'; readonly error: RateLimiterError };

interface WirePayload {
  identifier: string;
  action: string;
  limit: number;
  windowSeconds: number;
  ip?: string;
  ipLimit?: number;
}

export class RateLimiter {
  /** ES private field: invisible to console.log / util.inspect / JSON.stringify. */
  readonly #apiKey: string;
  private readonly endpoint: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly backoffBaseMs: number;
  private readonly backoffMaxMs: number;
  private readonly failOpen: boolean;
  private readonly defaultAction: string;
  private readonly fetchImpl: FetchLike;
  private readonly onFailOpen: ((event: FailOpenEvent) => void) | null;
  private readonly blockCache: LocalBlockCache | null;

  constructor(apiKey: string, options: RateLimiterOptions = {}) {
    if (typeof apiKey !== 'string' || !API_KEY_PATTERN.test(apiKey)) {
      // Deliberately does not echo the key.
      throw new RateLimiterConfigError('apiKey is missing or malformed (expected rlk_…)');
    }
    this.#apiKey = apiKey;

    const rawBaseUrl = options.baseUrl ?? readEnv('RATELIMIT_API_URL');
    if (rawBaseUrl === undefined) {
      throw new RateLimiterConfigError('baseUrl is required (option or RATELIMIT_API_URL environment variable)');
    }
    let url: URL;
    try {
      url = new URL(rawBaseUrl);
    } catch {
      throw new RateLimiterConfigError('baseUrl must be an absolute URL');
    }
    const isLocal = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLocal)) {
      throw new RateLimiterConfigError('baseUrl must use https (http is allowed for localhost only)');
    }
    this.endpoint = `${url.toString().replace(/\/+$/, '')}/v1/check`;

    this.timeoutMs = options.timeoutMs ?? 1_000;
    this.maxRetries = options.maxRetries ?? MAX_RETRIES_CAP;
    this.backoffBaseMs = options.backoffBaseMs ?? 100;
    this.backoffMaxMs = options.backoffMaxMs ?? 1_000;
    this.failOpen = options.failOpen ?? true;
    this.defaultAction = options.defaultAction ?? 'default';
    this.onFailOpen = options.onFailOpen ?? null;
    this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));

    const cacheEnabled = options.localBlockCache ?? true;
    const cacheMax = options.localBlockCacheMaxEntries ?? 10_000;

    const configChecks: Array<[string, number, number, number]> = [
      ['timeoutMs', this.timeoutMs, 1, 60_000],
      ['maxRetries', this.maxRetries, 0, MAX_RETRIES_CAP],
      ['backoffBaseMs', this.backoffBaseMs, 0, 60_000],
      ['backoffMaxMs', this.backoffMaxMs, 0, 60_000],
      ['localBlockCacheMaxEntries', cacheMax, 1, 1_000_000],
    ];
    for (const [name, value, min, max] of configChecks) {
      if (!Number.isSafeInteger(value) || value < min || value > max) {
        throw new RateLimiterConfigError(`${name} must be an integer between ${min} and ${max}`);
      }
    }
    if (!ACTION_PATTERN.test(this.defaultAction)) {
      throw new RateLimiterConfigError('defaultAction must match ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$');
    }
    this.blockCache = cacheEnabled ? new LocalBlockCache(cacheMax) : null;
  }

  /**
   * Check (and, if allowed, consume) one request for `identifier`.
   *
   * Resolves for both allowed and blocked outcomes — inspect `success`.
   * Rejects only for programmer errors (validation / auth) or, with
   * failOpen disabled, when the service is unreachable.
   */
  async check(
    identifier: string,
    limit: number,
    windowInSeconds: number,
    options: CheckOptions = {},
  ): Promise<RateLimitResponse> {
    const payload = this.buildPayload(identifier, limit, windowInSeconds, options);
    const cacheKey = JSON.stringify([
      payload.action,
      payload.identifier,
      payload.ip ?? null,
      payload.limit,
      payload.windowSeconds,
      payload.ipLimit ?? null,
    ]);

    const cached = this.blockCache?.get(cacheKey);
    if (cached !== undefined) {
      return cached;
    }

    let lastError: unknown = null;
    const totalAttempts = this.maxRetries + 1;

    for (let attempt = 0; attempt < totalAttempts; attempt += 1) {
      if (attempt > 0) {
        await this.sleep(this.backoffDelay(attempt - 1), options.signal);
      }
      const outcome = await this.attempt(payload, options.signal);
      if (outcome.kind === 'decision') {
        this.rememberBlock(cacheKey, outcome.response, outcome.resetAfterMs, windowInSeconds);
        return outcome.response;
      }
      if (outcome.kind === 'fatal') {
        throw outcome.error;
      }
      lastError = outcome.error;
    }

    if (!this.failOpen) {
      throw new RateLimiterUnavailableError(totalAttempts, lastError);
    }
    if (this.onFailOpen !== null) {
      try {
        this.onFailOpen({ error: lastError, attempts: totalAttempts, action: payload.action });
      } catch {
        // An observability hook must never break request handling.
      }
    }
    return {
      success: true,
      limit,
      remaining: limit,
      reset: Date.now() + windowInSeconds * 1_000,
      isBlocked: false,
      reason: 'fail_open',
    };
  }

  /** Safe representation for logs: never includes the key. */
  toJSON(): { endpoint: string } {
    return { endpoint: this.endpoint };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `RateLimiter { endpoint: '${this.endpoint}' }`;
  }

  /** Drop all locally cached blocks (e.g. after an operator unblocks a user). */
  clearLocalCache(): void {
    this.blockCache?.clear();
  }

  private buildPayload(
    identifier: string,
    limit: number,
    windowInSeconds: number,
    options: CheckOptions,
  ): WirePayload {
    if (typeof identifier !== 'string' || identifier.length === 0 || identifier.length > IDENTIFIER_MAX_LENGTH) {
      throw new RateLimiterValidationError(`identifier must be a string of 1-${IDENTIFIER_MAX_LENGTH} characters`);
    }
    assertInteger('limit', limit, 1, LIMIT_MAX);
    assertInteger('windowInSeconds', windowInSeconds, 1, WINDOW_MAX_SECONDS);

    const action = options.action ?? this.defaultAction;
    if (typeof action !== 'string' || !ACTION_PATTERN.test(action)) {
      throw new RateLimiterValidationError('action must match ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$');
    }

    const payload: WirePayload = { identifier, action, limit, windowSeconds: windowInSeconds };
    if (options.ip !== undefined) {
      if (typeof options.ip !== 'string' || options.ip.trim() === '' || options.ip.length > IP_MAX_LENGTH) {
        throw new RateLimiterValidationError('ip must be a non-empty string of at most 64 characters');
      }
      payload.ip = options.ip.trim();
    }
    if (options.ipLimit !== undefined) {
      if (payload.ip === undefined) {
        throw new RateLimiterValidationError('ipLimit requires ip');
      }
      assertInteger('ipLimit', options.ipLimit, 1, LIMIT_MAX);
      payload.ipLimit = options.ipLimit;
    }
    return payload;
  }

  private async attempt(payload: WirePayload, callerSignal: AbortSignal | undefined): Promise<Attempt> {
    if (isAborted(callerSignal)) {
      return { kind: 'fatal', error: new RateLimiterError('Rate limit check aborted', { cause: callerSignal?.reason }) };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const onCallerAbort = (): void => controller.abort();
    callerSignal?.addEventListener('abort', onCallerAbort, { once: true });

    try {
      let response: Response;
      try {
        response = await this.fetchImpl(this.endpoint, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${this.#apiKey}`,
            'content-type': 'application/json',
            accept: 'application/json',
            'x-sdk-version': `node/${SDK_VERSION}`,
          },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
      } catch (error: unknown) {
        if (isAborted(callerSignal)) {
          return { kind: 'fatal', error: new RateLimiterError('Rate limit check aborted', { cause: error }) };
        }
        return { kind: 'retryable', error };
      }

      if (response.status === 200 || response.status === 429) {
        let body: unknown;
        try {
          body = await response.json();
        } catch (error: unknown) {
          return { kind: 'retryable', error };
        }
        if (!isRateLimitResponse(body)) {
          // e.g. an upstream proxy's own 429 page: not a decision we can trust.
          return { kind: 'retryable', error: new RateLimiterError(`Unexpected response body (HTTP ${response.status})`) };
        }
        const header = response.headers.get('x-ratelimit-reset-after-ms');
        const resetAfterMs = header !== null && /^\d+$/.test(header) ? Number.parseInt(header, 10) : null;
        return { kind: 'decision', response: toResponse(body), resetAfterMs };
      }

      if (NON_RETRYABLE_4XX.has(response.status)) {
        let code = 'http_error';
        let message = 'Request rejected by rate limit service';
        let requestId = response.headers.get('x-request-id');
        try {
          const body: unknown = await response.json();
          if (isRecord(body)) {
            if (typeof body['error'] === 'string') code = body['error'];
            if (typeof body['message'] === 'string') message = body['message'];
            if (requestId === null && typeof body['requestId'] === 'string') requestId = body['requestId'];
          }
        } catch {
          // Keep the generic message.
        }
        return { kind: 'fatal', error: new RateLimiterHttpError(response.status, code, message, requestId) };
      }

      // 5xx, 408, and anything unexpected: retry with backoff.
      await response.body?.cancel().catch(() => undefined);
      return { kind: 'retryable', error: new RateLimiterError(`Rate limit service returned HTTP ${response.status}`) };
    } finally {
      clearTimeout(timer);
      callerSignal?.removeEventListener('abort', onCallerAbort);
    }
  }

  /** Exponential backoff with "equal jitter": spreads retries so clients do not stampede in lockstep. */
  private backoffDelay(retryIndex: number): number {
    const exp = Math.min(this.backoffMaxMs, this.backoffBaseMs * 2 ** retryIndex);
    return exp / 2 + Math.random() * (exp / 2);
  }

  private sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
    return new Promise((resolve, reject) => {
      if (isAborted(signal)) {
        reject(new RateLimiterError('Rate limit check aborted', { cause: signal?.reason }));
        return;
      }
      const onAbort = (): void => {
        clearTimeout(timer);
        reject(new RateLimiterError('Rate limit check aborted', { cause: signal?.reason }));
      };
      const timer = setTimeout(() => {
        signal?.removeEventListener('abort', onAbort);
        resolve();
      }, ms);
      signal?.addEventListener('abort', onAbort, { once: true });
    });
  }

  private rememberBlock(
    cacheKey: string,
    response: RateLimitResponse,
    resetAfterMs: number | null,
    windowInSeconds: number,
  ): void {
    if (this.blockCache === null || response.success || response.reason === 'fail_open') {
      return;
    }
    const windowCap = windowInSeconds * 2_000;
    // Prefer the server-measured duration (drift-proof); fall back to the
    // absolute reset compared against the local wall clock.
    const ttl = resetAfterMs ?? response.reset - Date.now();
    this.blockCache.set(cacheKey, response, Math.min(Math.max(ttl, 0), windowCap));
  }
}

export default RateLimiter;
