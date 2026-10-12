/**
 * Rate-limit orchestration: bucket key derivation, the atomic Redis check,
 * and the isolate-level block cache that shields Redis from floods.
 */

import { TtlLruCache } from './cache';
import { sha256Hex } from './crypto';
import { SLIDING_WINDOW_SCRIPT } from './lua';
import { RedisUnavailableError, type RedisReply, type UpstashRestClient } from './redis';
import type { CheckRequest } from './validation';

export type RateLimitReason = 'rate_limited' | 'ip_rate_limited' | 'fail_open';
export type DecisionSource = 'redis' | 'edge_cache' | 'fail_open';

/** Wire-level decision. `reset` is a Unix timestamp in milliseconds. */
export interface RateLimitDecision {
  readonly success: boolean;
  readonly limit: number;
  readonly remaining: number;
  readonly reset: number;
  readonly isBlocked: boolean;
  readonly reason?: RateLimitReason;
}

export interface EvaluatedDecision {
  readonly decision: RateLimitDecision;
  /** ms until `reset`, measured on the Redis clock — immune to edge clock drift. */
  readonly resetAfterMs: number;
  readonly source: DecisionSource;
}

export type BucketKind = 'identifier' | 'ip';

export interface Bucket {
  readonly kind: BucketKind;
  readonly key: string;
  readonly limit: number;
}

/**
 * Derive Redis keys. Identifiers and IPs are hashed so customer PII (emails,
 * user IDs, IPs) never sits in Redis in clear text and key length is bounded.
 * The `{tenant:action}` hash tag pins every bucket of one check to the same
 * cluster slot, which multi-key Lua scripts require.
 */
export async function deriveBuckets(tenantId: string, request: CheckRequest): Promise<Bucket[]> {
  const tag = `{${tenantId}:${request.action}}`;
  const scope = `rl:${tag}:w${request.windowSeconds}`;
  const identifierHash = await sha256Hex(`id\u0000${request.identifier}`);
  const buckets: Bucket[] = [{ kind: 'identifier', key: `${scope}:id:${identifierHash}`, limit: request.limit }];
  if (request.ip !== null) {
    const ipHash = await sha256Hex(`ip\u0000${request.ip}`);
    buckets.push({ kind: 'ip', key: `${scope}:ip:${ipHash}`, limit: request.ipLimit ?? request.limit });
  }
  return buckets;
}

interface BucketOutcome {
  readonly bucket: Bucket;
  readonly limit: number;
  readonly remaining: number;
  readonly reset: number;
  readonly ok: boolean;
}

function toInteger(value: RedisReply | undefined): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  if (typeof value === 'string' && /^-?\d+$/.test(value)) {
    return Number.parseInt(value, 10);
  }
  throw new RedisUnavailableError('protocol', 'Rate limit script returned a non-integer value');
}

export function parseScriptReply(
  reply: RedisReply,
  buckets: readonly Bucket[],
): { allowed: boolean; nowMs: number; outcomes: BucketOutcome[] } {
  if (!Array.isArray(reply) || reply.length !== 2 + buckets.length * 4) {
    throw new RedisUnavailableError('protocol', 'Rate limit script returned an unexpected shape');
  }
  const allowed = toInteger(reply[0]) === 1;
  const nowMs = toInteger(reply[1]);
  const outcomes = buckets.map((bucket, i) => {
    const base = 2 + i * 4;
    return {
      bucket,
      limit: toInteger(reply[base]),
      remaining: toInteger(reply[base + 1]),
      reset: toInteger(reply[base + 2]),
      ok: toInteger(reply[base + 3]) === 1,
    };
  });
  return { allowed, nowMs, outcomes };
}

/** Collapse per-bucket outcomes into the single decision the client sees. */
export function aggregate(allowed: boolean, nowMs: number, outcomes: readonly BucketOutcome[]): EvaluatedDecision {
  const first = outcomes[0];
  if (first === undefined) {
    throw new Error('aggregate() requires at least one bucket');
  }

  if (allowed) {
    // Report the most constrained bucket so callers see the tightest budget.
    let binding = first;
    for (const outcome of outcomes) {
      if (outcome.remaining < binding.remaining) {
        binding = outcome;
      }
    }
    return {
      decision: {
        success: true,
        limit: binding.limit,
        remaining: binding.remaining,
        reset: binding.reset,
        isBlocked: false,
      },
      resetAfterMs: Math.max(0, binding.reset - nowMs),
      source: 'redis',
    };
  }

  // Denied: the caller can only retry once EVERY failing bucket has room.
  const failing = outcomes.filter((o) => !o.ok);
  let binding = failing[0] ?? first;
  for (const outcome of failing) {
    if (outcome.reset > binding.reset) {
      binding = outcome;
    }
  }
  const identifierFailed = failing.some((o) => o.bucket.kind === 'identifier');
  return {
    decision: {
      success: false,
      limit: binding.limit,
      remaining: 0,
      reset: binding.reset,
      isBlocked: true,
      reason: identifierFailed ? 'rate_limited' : 'ip_rate_limited',
    },
    resetAfterMs: Math.max(0, binding.reset - nowMs),
    source: 'redis',
  };
}

export async function evaluate(
  redis: UpstashRestClient,
  buckets: readonly Bucket[],
  windowSeconds: number,
): Promise<EvaluatedDecision> {
  const reply = await redis.evalScript(
    SLIDING_WINDOW_SCRIPT,
    buckets.map((b) => b.key),
    [windowSeconds * 1_000, Date.now(), ...buckets.map((b) => b.limit)],
  );
  const { allowed, nowMs, outcomes } = parseScriptReply(reply, buckets);
  return aggregate(allowed, nowMs, outcomes);
}

/**
 * Fail-open decision: used when Redis is unreachable or slow. The client's
 * application keeps working; `remaining` is not authoritative in this mode.
 */
export function failOpenDecision(request: CheckRequest): EvaluatedDecision {
  const windowMs = request.windowSeconds * 1_000;
  return {
    decision: {
      success: true,
      limit: request.limit,
      remaining: request.limit,
      reset: Date.now() + windowMs,
      isBlocked: false,
      reason: 'fail_open',
    },
    resetAfterMs: windowMs,
    source: 'fail_open',
  };
}

// ---------------------------------------------------------------------------
// Edge block cache (thundering-herd shield)
// ---------------------------------------------------------------------------

interface CachedBlock {
  readonly limit: number;
  /** Absolute reset on the Redis clock (what clients are told). */
  readonly reset: number;
  /** Same instant expressed on THIS isolate's clock, for Retry-After math. */
  readonly localResetAt: number;
  readonly reason: RateLimitReason;
}

/** Upper bound on how long one isolate trusts a cached block before re-asking Redis. */
export const MAX_BLOCK_CACHE_MS = 60_000;
const blockCache = new TtlLruCache<CachedBlock>(50_000);

export function blockCacheKey(buckets: readonly Bucket[]): string {
  return buckets.map((b) => `${b.key}#${b.limit}`).join('|');
}

/**
 * Serve a denial straight from isolate memory. A blocked bot hammering the
 * endpoint costs one Redis call per isolate per block period instead of one
 * per request.
 */
export function lookupCachedBlock(buckets: readonly Bucket[]): EvaluatedDecision | null {
  const key = blockCacheKey(buckets);
  const cached = blockCache.get(key);
  if (cached === undefined) {
    return null;
  }
  const remainingMs = cached.localResetAt - Date.now();
  if (remainingMs <= 0) {
    blockCache.delete(key);
    return null;
  }
  return {
    decision: {
      success: false,
      limit: cached.limit,
      remaining: 0,
      reset: cached.reset,
      isBlocked: true,
      reason: cached.reason,
    },
    resetAfterMs: remainingMs,
    source: 'edge_cache',
  };
}

export function rememberBlock(buckets: readonly Bucket[], evaluated: EvaluatedDecision): void {
  const { decision } = evaluated;
  if (decision.success || decision.reason === undefined || decision.reason === 'fail_open') {
    return;
  }
  // resetAfterMs is a *duration* measured on the Redis clock; anchoring it to
  // the local clock means drift between this PoP and Redis can neither
  // extend nor shorten the block.
  const localNow = Date.now();
  const ttl = Math.min(evaluated.resetAfterMs, MAX_BLOCK_CACHE_MS);
  blockCache.set(
    blockCacheKey(buckets),
    {
      limit: decision.limit,
      reset: decision.reset,
      localResetAt: localNow + evaluated.resetAfterMs,
      reason: decision.reason,
    },
    ttl,
  );
}

/** Test hook. */
export function clearBlockCache(): void {
  blockCache.clear();
}
