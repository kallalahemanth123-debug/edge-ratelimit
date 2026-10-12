import { describe, expect, it } from 'vitest';
import {
  type FetchLike,
  RateLimiter,
  RateLimiterConfigError,
  RateLimiterHttpError,
  RateLimiterUnavailableError,
  RateLimiterValidationError,
} from '../src/index';

const KEY = `rlk_${'A'.repeat(43)}0123abcd`;
const BASE = 'https://rl.example.com';

function decision(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { success: true, limit: 10, remaining: 9, reset: Date.now() + 60_000, isBlocked: false, ...overrides };
}

function scripted(responses: Array<() => Response | Promise<Response>>): { fetch: FetchLike; calls: () => number } {
  let i = 0;
  return {
    fetch: async () => {
      const next = responses[Math.min(i, responses.length - 1)];
      i += 1;
      if (next === undefined) throw new Error('no response scripted');
      return next();
    },
    calls: () => i,
  };
}

const fast = { backoffBaseMs: 1, backoffMaxMs: 2 } as const;

describe('RateLimiter construction', () => {
  it('rejects malformed keys and insecure base URLs', () => {
    expect(() => new RateLimiter('nope', { baseUrl: BASE })).toThrow(RateLimiterConfigError);
    expect(() => new RateLimiter(KEY, { baseUrl: 'http://rl.example.com' })).toThrow(/https/);
    expect(() => new RateLimiter(KEY, { baseUrl: BASE, maxRetries: 3 })).toThrow(/maxRetries/);
    expect(() => new RateLimiter(KEY, { baseUrl: 'http://localhost:8787' })).not.toThrow();
  });

  it('never exposes the API key through serialisation or inspection', async () => {
    const limiter = new RateLimiter(KEY, { baseUrl: BASE });
    const utilModule = 'node:util'; // non-literal specifier: no @types/node needed
    const { inspect } = (await import(utilModule)) as { inspect: (value: unknown, opts: object) => string };
    expect(JSON.stringify(limiter)).not.toContain(KEY);
    expect(inspect(limiter, { depth: 10, showHidden: true })).not.toContain(KEY);
    expect(String(Object.values(limiter))).not.toContain(KEY);
  });
});

describe('RateLimiter.check', () => {
  it('returns the strictly typed decision and sends the right payload', async () => {
    let seen: { url: string; init: RequestInit } | null = null;
    const limiter = new RateLimiter(KEY, {
      baseUrl: `${BASE}/`,
      fetch: async (url, init) => {
        seen = { url, init };
        return Response.json(decision());
      },
    });
    const result = await limiter.check('user-1', 10, 60, { action: 'llm_generation', ip: '203.0.113.5', ipLimit: 50 });
    expect(result).toEqual({ success: true, limit: 10, remaining: 9, reset: expect.any(Number), isBlocked: false });
    expect(seen).not.toBeNull();
    const captured = seen as unknown as { url: string; init: RequestInit };
    expect(captured.url).toBe(`${BASE}/v1/check`);
    expect(JSON.parse(String(captured.init.body))).toEqual({
      identifier: 'user-1',
      action: 'llm_generation',
      limit: 10,
      windowSeconds: 60,
      ip: '203.0.113.5',
      ipLimit: 50,
    });
  });

  it('treats 429 as a decision, not an error', async () => {
    const limiter = new RateLimiter(KEY, {
      baseUrl: BASE,
      fetch: async () =>
        Response.json(decision({ success: false, remaining: 0, isBlocked: true, reason: 'rate_limited' }), { status: 429 }),
    });
    const result = await limiter.check('u', 10, 60);
    expect(result.success).toBe(false);
    expect(result.isBlocked).toBe(true);
    expect(result.reason).toBe('rate_limited');
  });

  it('retries 5xx with backoff, at most 2 retries, then succeeds', async () => {
    const script = scripted([
      () => new Response('boom', { status: 500 }),
      () => new Response('boom', { status: 503 }),
      () => Response.json(decision()),
    ]);
    const limiter = new RateLimiter(KEY, { baseUrl: BASE, fetch: script.fetch, ...fast });
    await expect(limiter.check('u', 10, 60)).resolves.toMatchObject({ success: true });
    expect(script.calls()).toBe(3);
  });

  it('fails open after exhausting retries and reports it', async () => {
    const script = scripted([() => new Response('boom', { status: 500 })]);
    const events: number[] = [];
    const limiter = new RateLimiter(KEY, {
      baseUrl: BASE,
      fetch: script.fetch,
      onFailOpen: (e) => events.push(e.attempts),
      ...fast,
    });
    const result = await limiter.check('u', 10, 60);
    expect(result).toMatchObject({ success: true, isBlocked: false, reason: 'fail_open', limit: 10 });
    expect(script.calls()).toBe(3);
    expect(events).toEqual([3]);
  });

  it('throws when failOpen is disabled', async () => {
    const script = scripted([
      () => {
        throw new TypeError('fetch failed');
      },
    ]);
    const limiter = new RateLimiter(KEY, { baseUrl: BASE, fetch: script.fetch, failOpen: false, ...fast });
    await expect(limiter.check('u', 10, 60)).rejects.toBeInstanceOf(RateLimiterUnavailableError);
    expect(script.calls()).toBe(3);
  });

  it('retries timeouts', async () => {
    const script = scripted([
      () => new Promise<Response>(() => undefined),
      () => Response.json(decision()),
    ]);
    const limiter = new RateLimiter(KEY, {
      baseUrl: BASE,
      timeoutMs: 20,
      ...fast,
      fetch: (url, init) =>
        new Promise((resolve, reject) => {
          init.signal?.addEventListener('abort', () => reject(new DOMException('timeout', 'AbortError')));
          void script.fetch(url, init).then(resolve, reject);
        }),
    });
    await expect(limiter.check('u', 10, 60)).resolves.toMatchObject({ success: true });
    expect(script.calls()).toBe(2);
  });

  it('does not retry or fail open on 401', async () => {
    const script = scripted([
      () =>
        Response.json(
          { error: 'invalid_api_key', message: 'API key is invalid, expired or revoked', requestId: 'r1' },
          { status: 401 },
        ),
    ]);
    const limiter = new RateLimiter(KEY, { baseUrl: BASE, fetch: script.fetch, ...fast });
    const error = await limiter.check('u', 10, 60).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RateLimiterHttpError);
    expect((error as RateLimiterHttpError).status).toBe(401);
    expect((error as RateLimiterHttpError).code).toBe('invalid_api_key');
    expect(script.calls()).toBe(1);
  });

  it('retries a malformed 200 body instead of trusting it', async () => {
    const script = scripted([() => Response.json({ hello: 'world' }), () => Response.json(decision())]);
    const limiter = new RateLimiter(KEY, { baseUrl: BASE, fetch: script.fetch, ...fast });
    await expect(limiter.check('u', 10, 60)).resolves.toMatchObject({ success: true });
    expect(script.calls()).toBe(2);
  });

  it('serves repeated blocked checks from the local cache', async () => {
    const script = scripted([
      () =>
        Response.json(decision({ success: false, remaining: 0, isBlocked: true, reason: 'rate_limited' }), {
          status: 429,
          headers: { 'x-ratelimit-reset-after-ms': '5000' },
        }),
    ]);
    const limiter = new RateLimiter(KEY, { baseUrl: BASE, fetch: script.fetch });
    for (let i = 0; i < 100; i += 1) {
      const result = await limiter.check('bot', 10, 60);
      expect(result.isBlocked).toBe(true);
    }
    expect(script.calls()).toBe(1);
    // A different subject is not affected.
    await limiter.check('human', 10, 60);
    expect(script.calls()).toBe(2);
  });

  it('validates arguments before any network I/O', async () => {
    const script = scripted([() => Response.json(decision())]);
    const limiter = new RateLimiter(KEY, { baseUrl: BASE, fetch: script.fetch });
    await expect(limiter.check('', 10, 60)).rejects.toBeInstanceOf(RateLimiterValidationError);
    await expect(limiter.check('u', 0, 60)).rejects.toBeInstanceOf(RateLimiterValidationError);
    await expect(limiter.check('u', 10, 1.5)).rejects.toBeInstanceOf(RateLimiterValidationError);
    await expect(limiter.check('u', 10, 60, { ipLimit: 5 })).rejects.toThrow(/ipLimit requires ip/);
    await expect(limiter.check('u', 10, 60, { action: 'bad action' })).rejects.toBeInstanceOf(
      RateLimiterValidationError,
    );
    expect(script.calls()).toBe(0);
  });

  it('propagates caller aborts without failing open', async () => {
    const controller = new AbortController();
    controller.abort();
    const limiter = new RateLimiter(KEY, { baseUrl: BASE, fetch: async () => Response.json(decision()) });
    await expect(limiter.check('u', 10, 60, { signal: controller.signal })).rejects.toThrow(/aborted/);
  });
});
