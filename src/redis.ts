/**
 * Minimal, dependency-free Upstash Redis REST client.
 *
 * Written by hand (instead of @upstash/redis) for three reasons:
 *  1. A hard per-call timeout via AbortController — the basis of fail-open.
 *  2. Precise error classification: "Redis is unavailable" (fail open) vs.
 *     "the command itself failed" (a bug or NOSCRIPT, handled explicitly).
 *  3. EVALSHA-first script execution with automatic NOSCRIPT fallback, so the
 *     Lua source is only sent over the wire once per Redis instance.
 */

import { sha1Hex } from './crypto';

export type RedisArg = string | number;
export type RedisReply = string | number | null | RedisReply[];

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

const NOSCRIPT_PATTERN = /^NOSCRIPT\b|No matching script/i;

/** Redis could not be reached in time, rejected our credentials, or returned garbage. */
export class RedisUnavailableError extends Error {
  readonly reason: 'timeout' | 'network' | 'auth' | 'http' | 'protocol';

  constructor(reason: RedisUnavailableError['reason'], message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'RedisUnavailableError';
    this.reason = reason;
  }
}

/** Redis was reachable and executed the request, but the command returned an error reply. */
export class RedisCommandError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RedisCommandError';
  }
}

export class LuaScript {
  readonly source: string;
  private shaPromise: Promise<string> | null = null;

  constructor(source: string) {
    this.source = source;
  }

  sha(): Promise<string> {
    if (this.shaPromise === null) {
      this.shaPromise = sha1Hex(this.source);
    }
    return this.shaPromise;
  }
}

function isRedisReply(value: unknown): value is RedisReply {
  if (value === null || typeof value === 'string' || typeof value === 'number') {
    return true;
  }
  return Array.isArray(value) && value.every(isRedisReply);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

type Envelope = { kind: 'result'; value: RedisReply } | { kind: 'error'; message: string };

function parseEnvelope(value: unknown): Envelope | null {
  if (!isRecord(value)) {
    return null;
  }
  const error = value['error'];
  if (typeof error === 'string') {
    return { kind: 'error', message: error };
  }
  if (!('result' in value)) {
    return null;
  }
  const result = value['result'];
  return isRedisReply(result) ? { kind: 'result', value: result } : null;
}

export interface UpstashClientOptions {
  readonly url: string;
  readonly token: string;
  readonly timeoutMs: number;
  readonly fetch?: FetchLike;
}

export class UpstashRestClient {
  private readonly url: string;
  private readonly token: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: FetchLike;

  constructor(options: UpstashClientOptions) {
    this.url = options.url;
    this.token = options.token;
    this.timeoutMs = options.timeoutMs;
    // Wrapping matters: calling an unbound global `fetch` stored on an object
    // throws "Illegal invocation" in workerd.
    this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
  }

  async command(args: readonly RedisArg[]): Promise<RedisReply> {
    const body = await this.post(this.url, args.map(String));
    const envelope = parseEnvelope(body);
    if (envelope === null) {
      throw new RedisUnavailableError('protocol', 'Malformed Upstash response envelope');
    }
    if (envelope.kind === 'error') {
      throw new RedisCommandError(envelope.message);
    }
    return envelope.value;
  }

  /**
   * Non-transactional pipeline: one HTTP round trip, per-command results.
   * Command errors are surfaced per entry rather than failing the batch.
   */
  async pipeline(commands: readonly (readonly RedisArg[])[]): Promise<Array<RedisReply | RedisCommandError>> {
    if (commands.length === 0) {
      return [];
    }
    const body = await this.post(
      `${this.url}/pipeline`,
      commands.map((cmd) => cmd.map(String)),
    );
    if (!Array.isArray(body) || body.length !== commands.length) {
      throw new RedisUnavailableError('protocol', 'Malformed Upstash pipeline response');
    }
    return body.map((entry: unknown) => {
      const envelope = parseEnvelope(entry);
      if (envelope === null) {
        throw new RedisUnavailableError('protocol', 'Malformed Upstash pipeline entry');
      }
      return envelope.kind === 'error' ? new RedisCommandError(envelope.message) : envelope.value;
    });
  }

  /** EVALSHA with transparent fallback to EVAL (which also caches the script server-side). */
  async evalScript(script: LuaScript, keys: readonly string[], args: readonly RedisArg[]): Promise<RedisReply> {
    const sha = await script.sha();
    try {
      return await this.command(['EVALSHA', sha, keys.length, ...keys, ...args]);
    } catch (error: unknown) {
      if (error instanceof RedisCommandError && NOSCRIPT_PATTERN.test(error.message)) {
        return this.command(['EVAL', script.source, keys.length, ...keys, ...args]);
      }
      throw error;
    }
  }

  private async post(url: string, payload: unknown): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
    } catch (error: unknown) {
      clearTimeout(timer);
      if (controller.signal.aborted) {
        throw new RedisUnavailableError('timeout', `Redis did not respond within ${this.timeoutMs}ms`, {
          cause: error,
        });
      }
      throw new RedisUnavailableError('network', 'Redis request failed', { cause: error });
    }

    try {
      if (response.status === 401 || response.status === 403) {
        await response.body?.cancel();
        throw new RedisUnavailableError('auth', `Redis rejected credentials (HTTP ${response.status})`);
      }
      // Upstash reports command errors (e.g. NOSCRIPT, WRONGTYPE) as 4xx with
      // an {"error": "..."} body; 5xx means the service itself is unhealthy.
      if (response.status >= 500) {
        await response.body?.cancel();
        throw new RedisUnavailableError('http', `Redis returned HTTP ${response.status}`);
      }
      let parsed: unknown;
      try {
        parsed = await response.json();
      } catch (error: unknown) {
        if (controller.signal.aborted) {
          throw new RedisUnavailableError('timeout', `Redis did not respond within ${this.timeoutMs}ms`, {
            cause: error,
          });
        }
        throw new RedisUnavailableError('protocol', 'Redis returned a non-JSON body', { cause: error });
      }
      if (!response.ok && parseEnvelope(parsed)?.kind !== 'error') {
        throw new RedisUnavailableError('http', `Redis returned HTTP ${response.status}`);
      }
      return parsed;
    } finally {
      clearTimeout(timer);
    }
  }
}

/** Parse a flat HGETALL reply (["field", "value", ...]) into a record. */
export function hashReplyToRecord(reply: RedisReply): Record<string, string> | null {
  if (!Array.isArray(reply)) {
    throw new RedisUnavailableError('protocol', 'HGETALL reply is not an array');
  }
  if (reply.length === 0) {
    return null;
  }
  if (reply.length % 2 !== 0) {
    throw new RedisUnavailableError('protocol', 'HGETALL reply has odd length');
  }
  const record: Record<string, string> = {};
  for (let i = 0; i < reply.length; i += 2) {
    const field = reply[i];
    const value = reply[i + 1];
    if (typeof field !== 'string' || (typeof value !== 'string' && typeof value !== 'number')) {
      throw new RedisUnavailableError('protocol', 'HGETALL reply contains non-scalar entries');
    }
    record[field] = String(value);
  }
  return record;
}
