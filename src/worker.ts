/**
 * Edge rate-limit & abuse-protection API — Cloudflare Worker entry point.
 *
 *   POST /v1/check        decide whether one request may proceed
 *   GET  /health          liveness (no dependencies touched)
 *   /v1/admin/*           key management (see admin.ts)
 */

import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { admin } from './admin';
import type { AuthResult } from './apikeys';
import { type AppContext, type AppEnv, backgroundRunner, getServices, jsonError } from './context';
import { type Config, ConfigError, getConfig } from './env';
import { errorFields, Logger, redact } from './logger';
import {
  type Bucket,
  deriveBuckets,
  evaluate,
  type EvaluatedDecision,
  failOpenDecision,
  lookupCachedBlock,
  rememberBlock,
} from './ratelimit';
import { RedisUnavailableError } from './redis';
import { type CheckRequest, parseCheckRequest } from './validation';

const MAX_BODY_BYTES = 4 * 1024;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9-]{8,64}$/;

const app = new Hono<AppEnv>();

// --- Request context: request id, config validation, logger, services -------
app.use('*', async (c, next) => {
  const ray = c.req.header('cf-ray');
  const requestId = ray !== undefined && REQUEST_ID_PATTERN.test(ray) ? ray : crypto.randomUUID();
  c.set('requestId', requestId);

  let config: Config;
  try {
    config = getConfig(c.env);
  } catch (error: unknown) {
    const issues = error instanceof ConfigError ? error.issues.join('; ') : 'unknown';
    console.error(JSON.stringify({ level: 'error', event: 'config.invalid', requestId, issues }));
    return c.json({ error: 'service_misconfigured', message: 'Service misconfigured', requestId }, 500);
  }

  c.set('config', config);
  c.set('services', getServices(config));
  c.set(
    'logger',
    new Logger({
      requestId,
      environment: config.environment,
      drainUrl: config.logDrainUrl,
      drainToken: config.logDrainToken,
      waitUntil: backgroundRunner(c),
    }),
  );

  await next();

  c.header('X-Request-Id', requestId);
  c.header('Cache-Control', 'no-store');
  c.header('X-Content-Type-Options', 'nosniff');
  return undefined;
});

app.get('/health', (c) => c.json({ status: 'ok' }));

// --- Core endpoint -------------------------------------------------------------

function extractBearer(header: string | undefined): string | null {
  if (header === undefined) {
    return null;
  }
  const match = /^Bearer\s+(\S+)\s*$/i.exec(header);
  return match?.[1] ?? null;
}

function applyRateLimitHeaders(c: AppContext, evaluated: EvaluatedDecision): void {
  const { decision, resetAfterMs } = evaluated;
  c.header('X-RateLimit-Limit', String(decision.limit));
  c.header('X-RateLimit-Remaining', String(decision.remaining));
  c.header('X-RateLimit-Reset', String(Math.ceil(decision.reset / 1_000)));
  c.header('X-RateLimit-Reset-After-Ms', String(Math.max(0, Math.ceil(resetAfterMs))));
  if (evaluated.source === 'edge_cache') {
    c.header('X-RateLimit-Cache', 'HIT');
  }
  if (evaluated.source === 'fail_open') {
    c.header('X-RateLimit-Fail-Open', 'true');
  }
  if (!decision.success) {
    c.header('Retry-After', String(Math.max(1, Math.ceil(resetAfterMs / 1_000))));
  }
}

function respond(c: AppContext, evaluated: EvaluatedDecision): Response {
  applyRateLimitHeaders(c, evaluated);
  const { decision } = evaluated;
  const body: Record<string, unknown> = {
    success: decision.success,
    limit: decision.limit,
    remaining: decision.remaining,
    reset: decision.reset,
    isBlocked: decision.isBlocked,
  };
  if (decision.reason !== undefined) {
    body['reason'] = decision.reason;
  }
  return c.json(body, decision.success ? 200 : 429);
}

function failOpen(c: AppContext, request: CheckRequest, stage: string, error: unknown, keyHash: string | null): Response {
  const isOutage = error instanceof RedisUnavailableError;
  // Logged asynchronously (console + waitUntil drain); never blocks the reply.
  c.get('logger').error(isOutage ? 'ratelimit.fail_open' : 'ratelimit.fail_open_unexpected', {
    stage,
    redisFailure: isOutage ? error.reason : null,
    keyHashPrefix: keyHash === null ? null : keyHash.slice(0, 12),
    action: request.action,
    ...errorFields(error),
  });
  return respond(c, failOpenDecision(request));
}

app.post(
  '/v1/check',
  bodyLimit({
    maxSize: MAX_BODY_BYTES,
    onError: (c) => jsonError(c as AppContext, 413, 'payload_too_large', `Body must be at most ${MAX_BODY_BYTES} bytes`),
  }),
  async (c) => {
    const logger = c.get('logger');

    const presentedKey = extractBearer(c.req.header('authorization'));
    if (presentedKey === null) {
      c.header('WWW-Authenticate', 'Bearer realm="ratelimit"');
      return jsonError(c, 401, 'missing_api_key', 'Authorization: Bearer <api key> is required');
    }

    const contentType = c.req.header('content-type') ?? '';
    if (!/^application\/json\b/i.test(contentType)) {
      return jsonError(c, 415, 'unsupported_media_type', 'Content-Type must be application/json');
    }

    let rawBody: unknown;
    try {
      rawBody = await c.req.json();
    } catch {
      return jsonError(c, 400, 'invalid_json', 'Body is not valid JSON');
    }
    const parsed = parseCheckRequest(rawBody);
    if (!parsed.ok) {
      return jsonError(c, 400, 'invalid_request', 'Request validation failed', parsed.errors);
    }
    const request = parsed.value;

    // 1) Authenticate. The plaintext key is hashed inside authenticate()
    //    before any cache or Redis access and is never logged.
    let auth: AuthResult;
    try {
      auth = await c.get('services').keys.authenticate(presentedKey);
    } catch (error: unknown) {
      return failOpen(c, request, 'authenticate', error, null);
    }
    if (!auth.ok) {
      logger.warn('auth.rejected', {
        reason: auth.reason,
        keyHashPrefix: auth.keyHash === null ? null : auth.keyHash.slice(0, 12),
      });
      c.header('WWW-Authenticate', 'Bearer realm="ratelimit", error="invalid_token"');
      // One generic message for every failure mode: no oracle for attackers.
      return jsonError(c, 401, 'invalid_api_key', 'API key is invalid, expired or revoked');
    }

    // 2) Derive buckets and try the isolate-local block cache first.
    let evaluated: EvaluatedDecision;
    let buckets: Bucket[];
    try {
      buckets = await deriveBuckets(auth.record.tenantId, request);
      const cached = lookupCachedBlock(buckets);
      if (cached !== null) {
        return respond(c, cached);
      }
      // 3) Atomic sliding-window check in Redis.
      evaluated = await evaluate(c.get('services').redis, buckets, request.windowSeconds);
    } catch (error: unknown) {
      return failOpen(c, request, 'evaluate', error, auth.keyHash);
    }

    if (!evaluated.decision.success) {
      rememberBlock(buckets, evaluated);
    }
    return respond(c, evaluated);
  },
);

app.route('/v1/admin', admin);

app.notFound((c) => c.json({ error: 'not_found', message: 'Not found' }, 404));

app.onError((error, c) => {
  const requestId = c.get('requestId');
  console.error(
    redact(JSON.stringify({ level: 'error', event: 'unhandled_error', requestId: requestId ?? null, ...errorFields(error) })),
  );
  return c.json({ error: 'internal_error', message: 'Unexpected error', requestId: requestId ?? null }, 500);
});

export default app;
