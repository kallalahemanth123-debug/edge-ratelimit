#!/usr/bin/env node
/**
 * Runtime smoke test for the BUILT package (dist/), with no dev dependencies.
 * CI runs it on every Node version the SDK supports (>= 18.17), including
 * versions the test tooling itself cannot run on.
 *
 *   npm run build && node test/smoke.mjs
 */

import assert from 'node:assert/strict';
import { RateLimiter, RateLimiterHttpError } from '../dist/index.js';

const KEY = `rlk_${'A'.repeat(43)}0123abcd`;
const BASE = 'https://rl.example.com';

const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

const decision = (overrides = {}) => ({
  success: true,
  limit: 10,
  remaining: 9,
  reset: Date.now() + 60_000,
  isBlocked: false,
  ...overrides,
});

function scripted(responses) {
  let calls = 0;
  return {
    fetch: async () => responses[Math.min(calls++, responses.length - 1)](),
    calls: () => calls,
  };
}

const fast = { backoffBaseMs: 1, backoffMaxMs: 2 };

// 1. Allowed decision round-trips with the exact public shape.
{
  const s = scripted([() => json(decision())]);
  const result = await new RateLimiter(KEY, { baseUrl: BASE, fetch: s.fetch }).check('u', 10, 60);
  assert.deepEqual(Object.keys(result).sort(), ['isBlocked', 'limit', 'remaining', 'reset', 'success']);
  assert.equal(result.success, true);
}

// 2. 5xx is retried with backoff, then succeeds.
{
  const s = scripted([() => new Response('x', { status: 500 }), () => json(decision())]);
  const result = await new RateLimiter(KEY, { baseUrl: BASE, fetch: s.fetch, ...fast }).check('u', 10, 60);
  assert.equal(result.success, true);
  assert.equal(s.calls(), 2);
}

// 3. Exhausted retries fail open (3 attempts total).
{
  const s = scripted([() => new Response('x', { status: 503 })]);
  const result = await new RateLimiter(KEY, { baseUrl: BASE, fetch: s.fetch, ...fast }).check('u', 10, 60);
  assert.equal(result.reason, 'fail_open');
  assert.equal(s.calls(), 3);
}

// 4. Timeouts abort via AbortController and are retried.
{
  let calls = 0;
  const fetchImpl = (_url, init) => {
    calls += 1;
    if (calls === 1) {
      return new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => reject(new Error('aborted')));
      });
    }
    return Promise.resolve(json(decision()));
  };
  const result = await new RateLimiter(KEY, { baseUrl: BASE, fetch: fetchImpl, timeoutMs: 20, ...fast }).check(
    'u',
    10,
    60,
  );
  assert.equal(result.success, true);
  assert.equal(calls, 2);
}

// 5. 401 throws a typed error and is not retried.
{
  const s = scripted([() => json({ error: 'invalid_api_key', message: 'bad key' }, 401)]);
  await assert.rejects(
    new RateLimiter(KEY, { baseUrl: BASE, fetch: s.fetch, ...fast }).check('u', 10, 60),
    (error) => error instanceof RateLimiterHttpError && error.status === 401,
  );
  assert.equal(s.calls(), 1);
}

// 6. Blocked decisions are served from the local cache (monotonic clock).
{
  const s = scripted([
    () =>
      json(decision({ success: false, remaining: 0, isBlocked: true, reason: 'rate_limited' }), 429, {
        'x-ratelimit-reset-after-ms': '5000',
      }),
  ]);
  const limiter = new RateLimiter(KEY, { baseUrl: BASE, fetch: s.fetch });
  for (let i = 0; i < 50; i += 1) {
    assert.equal((await limiter.check('bot', 10, 60)).isBlocked, true);
  }
  assert.equal(s.calls(), 1);
}

// 7. The key never leaks through serialisation.
{
  const limiter = new RateLimiter(KEY, { baseUrl: BASE });
  assert.ok(!JSON.stringify(limiter).includes(KEY));
}

console.log(`SDK runtime smoke test passed on Node ${process.version}`);
