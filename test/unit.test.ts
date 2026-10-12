import { describe, expect, it } from 'vitest';
import { TtlLruCache } from '../src/cache';
import { generateApiKey, isWellFormedApiKey, secretsEqual } from '../src/crypto';
import { ConfigError, parseConfig } from '../src/env';
import { redact } from '../src/logger';
import { aggregate, type Bucket, parseScriptReply } from '../src/ratelimit';
import { RedisCommandError, RedisUnavailableError, UpstashRestClient } from '../src/redis';
import { normalizeIp, parseCheckRequest } from '../src/validation';

describe('normalizeIp', () => {
  it('canonicalises IPv4 and rejects ambiguous forms', () => {
    expect(normalizeIp('203.0.113.9')).toBe('203.0.113.9');
    expect(normalizeIp(' 203.0.113.9 ')).toBe('203.0.113.9');
    expect(normalizeIp('203.0.113.09')).toBeNull();
    expect(normalizeIp('256.0.0.1')).toBeNull();
    expect(normalizeIp('1.2.3')).toBeNull();
  });

  it('collapses IPv6 to its /64 and unwraps IPv4-mapped addresses', () => {
    expect(normalizeIp('2001:db8:abcd:12:1:2:3:4')).toBe('2001:db8:abcd:12::/64');
    expect(normalizeIp('2001:DB8:ABCD:12::ffff')).toBe('2001:db8:abcd:12::/64');
    expect(normalizeIp('[2001:db8::1]')).toBe('2001:db8:0:0::/64');
    expect(normalizeIp('::ffff:198.51.100.7')).toBe('198.51.100.7');
    expect(normalizeIp('::1')).toBe('0:0:0:0::/64');
    expect(normalizeIp('fe80::1%eth0')).toBeNull();
    expect(normalizeIp('1::2::3')).toBeNull();
    expect(normalizeIp('1.2.3.4::')).toBeNull();
    expect(normalizeIp('12345::')).toBeNull();
  });
});

describe('parseCheckRequest', () => {
  it('accepts a valid request and applies defaults', () => {
    const result = parseCheckRequest({ identifier: 'u1', limit: 10, windowSeconds: 60 });
    expect(result).toEqual({
      ok: true,
      value: { identifier: 'u1', action: 'default', ip: null, limit: 10, windowSeconds: 60, ipLimit: null },
    });
  });

  it('rejects unknown fields, bad numbers and ipLimit without ip', () => {
    const result = parseCheckRequest({ identifier: '', limit: 0, windowSeconds: 1.5, ipLimit: 5, extra: true });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors).toEqual(
        expect.arrayContaining([
          'unknown field: extra',
          'identifier must be a non-empty string',
          'limit must be between 1 and 1000000',
          'windowSeconds must be an integer',
          'ipLimit requires ip',
        ]),
      );
    }
  });

  it('rejects actions that could break key namespacing', () => {
    const result = parseCheckRequest({ identifier: 'u', action: 'a}b', limit: 1, windowSeconds: 1 });
    expect(result.ok).toBe(false);
  });
});

describe('API keys', () => {
  it('generates keys that pass format + checksum validation', () => {
    for (let i = 0; i < 50; i += 1) {
      const key = generateApiKey();
      expect(key).toMatch(/^rlk_[A-Za-z0-9_-]{43}[0-9a-f]{8}$/);
      expect(isWellFormedApiKey(key)).toBe(true);
    }
  });

  it('rejects keys with a corrupted body (checksum mismatch)', () => {
    const key = generateApiKey();
    const flipped = `${key.slice(0, 10)}${key[10] === 'A' ? 'B' : 'A'}${key.slice(11)}`;
    expect(isWellFormedApiKey(flipped)).toBe(false);
    expect(isWellFormedApiKey('rlk_short')).toBe(false);
  });

  it('compares secrets in constant time semantics', async () => {
    expect(await secretsEqual('abc', 'abc')).toBe(true);
    expect(await secretsEqual('abc', 'abd')).toBe(false);
    expect(await secretsEqual('', 'abc')).toBe(false);
  });
});

describe('redact', () => {
  it('scrubs API keys and bearer tokens', () => {
    const key = generateApiKey();
    expect(redact(`key=${key}`)).toBe('key=rlk_[REDACTED]');
    expect(redact('Authorization: Bearer abcdefghijklmnop')).toBe('Authorization: Bearer [REDACTED]');
  });
});

describe('parseConfig', () => {
  it('requires Upstash credentials and https', () => {
    expect(() => parseConfig({})).toThrow(ConfigError);
    expect(() =>
      parseConfig({ UPSTASH_REDIS_REST_URL: 'http://db.upstash.io', UPSTASH_REDIS_REST_TOKEN: 'tok' }),
    ).toThrow(/https/);
  });

  it('allows http only for localhost in development and applies defaults', () => {
    const config = parseConfig({
      UPSTASH_REDIS_REST_URL: 'http://127.0.0.1:8079/',
      UPSTASH_REDIS_REST_TOKEN: 'token',
      ENVIRONMENT: 'development',
    });
    expect(config.redisUrl).toBe('http://127.0.0.1:8079');
    expect(config.redisTimeoutMs).toBe(250);
    expect(config.keyCacheTtlMs).toBe(30_000);
    expect(config.adminToken).toBeNull();
  });

  it('never echoes secret values in errors', () => {
    try {
      parseConfig({
        UPSTASH_REDIS_REST_URL: 'https://db.upstash.io',
        UPSTASH_REDIS_REST_TOKEN: 'super-secret-token',
        ADMIN_API_TOKEN: 'short-secret',
      });
      expect.unreachable();
    } catch (error: unknown) {
      expect(String(error)).not.toContain('short-secret');
      expect(String(error)).toContain('ADMIN_API_TOKEN');
    }
  });
});

describe('TtlLruCache', () => {
  it('expires entries and evicts least recently used', () => {
    let now = 0;
    const cache = new TtlLruCache<string>(2, () => now);
    cache.set('a', 'A', 100);
    cache.set('b', 'B', 100);
    expect(cache.get('a')).toBe('A'); // a is now most recent
    cache.set('c', 'C', 100); // evicts b
    expect(cache.get('b')).toBeUndefined();
    now = 101;
    expect(cache.get('a')).toBeUndefined();
  });
});

describe('aggregate', () => {
  const idBucket: Bucket = { kind: 'identifier', key: 'id', limit: 5 };
  const ipBucket: Bucket = { kind: 'ip', key: 'ip', limit: 10 };

  it('reports the tightest bucket when allowed', () => {
    const parsed = parseScriptReply([1, 1_000, 5, 3, 60_000, 1, 10, 1, 60_000, 1], [idBucket, ipBucket]);
    const result = aggregate(parsed.allowed, parsed.nowMs, parsed.outcomes);
    expect(result.decision).toEqual({ success: true, limit: 10, remaining: 1, reset: 60_000, isBlocked: false });
    expect(result.resetAfterMs).toBe(59_000);
  });

  it('blames the IP bucket when only it fails and waits for the latest reset', () => {
    const parsed = parseScriptReply([0, 1_000, 5, 4, 60_000, 1, 10, 0, 90_000, 0], [idBucket, ipBucket]);
    const result = aggregate(parsed.allowed, parsed.nowMs, parsed.outcomes);
    expect(result.decision).toEqual({
      success: false,
      limit: 10,
      remaining: 0,
      reset: 90_000,
      isBlocked: true,
      reason: 'ip_rate_limited',
    });
  });

  it('rejects malformed script replies', () => {
    expect(() => parseScriptReply([1, 2, 3], [idBucket])).toThrow(RedisUnavailableError);
  });
});

describe('UpstashRestClient', () => {
  const make = (impl: (url: string, init: RequestInit) => Promise<Response>, timeoutMs = 50) =>
    new UpstashRestClient({ url: 'https://redis.test', token: 't', timeoutMs, fetch: impl });

  it('times out slow responses as RedisUnavailableError(timeout)', async () => {
    const client = make(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        }),
    );
    await expect(client.command(['PING'])).rejects.toMatchObject({ name: 'RedisUnavailableError', reason: 'timeout' });
  });

  it('classifies 5xx as unavailable and 4xx error envelopes as command errors', async () => {
    const down = make(async () => new Response('oops', { status: 502 }));
    await expect(down.command(['PING'])).rejects.toMatchObject({ reason: 'http' });

    const bad = make(async () => Response.json({ error: 'WRONGTYPE nope' }, { status: 400 }));
    await expect(bad.command(['GET', 'x'])).rejects.toBeInstanceOf(RedisCommandError);

    const auth = make(async () => Response.json({ error: 'Unauthorized' }, { status: 401 }));
    await expect(auth.command(['PING'])).rejects.toMatchObject({ reason: 'auth' });
  });

  it('falls back from EVALSHA to EVAL on NOSCRIPT', async () => {
    const calls: string[] = [];
    const client = make(async (_url, init) => {
      const body = JSON.parse(String(init.body)) as string[];
      calls.push(body[0] ?? '');
      if (body[0] === 'EVALSHA') {
        return Response.json({ error: 'NOSCRIPT No matching script. Please use EVAL.' }, { status: 400 });
      }
      return Response.json({ result: 'OK' });
    });
    const { SLIDING_WINDOW_SCRIPT } = await import('../src/lua');
    await expect(client.evalScript(SLIDING_WINDOW_SCRIPT, ['k'], [1])).resolves.toBe('OK');
    expect(calls).toEqual(['EVALSHA', 'EVAL']);
  });
});
