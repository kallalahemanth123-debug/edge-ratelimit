#!/usr/bin/env node
/**
 * End-to-end test: real worker (wrangler dev / workerd) + real Redis (via the
 * Upstash REST emulator) + the built Node SDK.
 *
 *   redis-server --port 6390 &
 *   python dev/upstash_emulator.py --port 8079 --token dev-token-123456 --redis redis://127.0.0.1:6390/0 &
 *   (cd sdk/node && npm run build)
 *   npx wrangler dev --port 8787 &          # uses .dev.vars
 *   node dev/e2e.mjs
 *
 * Env: E2E_BASE_URL, E2E_ADMIN_TOKEN, E2E_EMULATOR_URL
 */

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { RateLimiter, RateLimiterHttpError } from '../sdk/node/dist/index.js';

const BASE = process.env.E2E_BASE_URL ?? 'http://127.0.0.1:8787';
const ADMIN = process.env.E2E_ADMIN_TOKEN ?? 'local-admin-token-0123456789abcdef0123';
const EMULATOR = process.env.E2E_EMULATOR_URL ?? 'http://127.0.0.1:8079';
const EMULATOR_TOKEN = process.env.E2E_EMULATOR_TOKEN ?? 'dev-token-123456';
// Must match the worker's REDIS_TIMEOUT_MS. The local Python emulator is far
// slower than Upstash under 100-way concurrency, so run e2e with e.g.
// `wrangler dev --var REDIS_TIMEOUT_MS:1500` and E2E_REDIS_TIMEOUT_MS=1500.
const REDIS_TIMEOUT_MS = Number(process.env.E2E_REDIS_TIMEOUT_MS ?? '250');
const run = randomUUID().slice(0, 8);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function admin(method, path, body) {
  const res = await fetch(`${BASE}/v1/admin${path}`, {
    method,
    headers: { authorization: `Bearer ${ADMIN}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

async function faults(delayMs, failStatus) {
  await fetch(`${EMULATOR}/__control`, { method: 'POST', body: JSON.stringify({ delayMs, failStatus }) });
}

async function redis(...args) {
  const res = await fetch(`${EMULATOR}/`, {
    method: 'POST',
    headers: { authorization: `Bearer ${EMULATOR_TOKEN}` },
    body: JSON.stringify(args),
  });
  return (await res.json()).result;
}

async function rawCheck(key, payload) {
  const res = await fetch(`${BASE}/v1/check`, {
    method: 'POST',
    headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return { status: res.status, headers: res.headers, body: await res.json() };
}

const results = [];
async function test(name, fn) {
  const started = performance.now();
  try {
    await fn();
    results.push({ name, ok: true, ms: Math.round(performance.now() - started) });
    console.log(`  ✓ ${name}`);
  } catch (error) {
    results.push({ name, ok: false });
    console.log(`  ✗ ${name}\n    ${error?.stack ?? error}`);
  }
}

const tenant = `e2e-${run}`;
const created = await admin('POST', `/tenants/${tenant}/keys`, { label: 'e2e primary' });
assert.equal(created.status, 201, JSON.stringify(created.body));
const apiKey = created.body.apiKey;
const keyId = created.body.key.keyId;

const limiter = (opts = {}) => new RateLimiter(apiKey, { baseUrl: BASE, ...opts });

console.log(`E2E against ${BASE} (tenant ${tenant})`);

await test('admin rejects bad credentials in constant-time path', async () => {
  const res = await fetch(`${BASE}/v1/admin/tenants/${tenant}/keys`, { headers: { authorization: 'Bearer wrong' } });
  assert.equal(res.status, 401);
});

await test('100 concurrent requests in the same instant → exactly `limit` allowed (atomic Lua)', async () => {
  const rl = limiter({ localBlockCache: false });
  const id = `race-${run}`;
  const outcomes = await Promise.all(
    Array.from({ length: 100 }, () => rl.check(id, 10, 60, { action: 'login_attempt' })),
  );
  const failOpen = outcomes.filter((o) => o.reason === 'fail_open').length;
  const allowed = outcomes.filter((o) => o.success && o.reason !== 'fail_open').length;
  const blocked = outcomes.filter((o) => o.isBlocked).length;
  assert.equal(failOpen, 0, `fail-open=${failOpen}: raise REDIS_TIMEOUT_MS for the local emulator`);
  assert.equal(allowed, 10, `allowed=${allowed}`);
  assert.equal(blocked, 90);
  // And the counter in Redis agrees: no lost or double increments.
  const [bucket] = await redis('KEYS', `rl:{${tenant}:login_attempt}:w60:id:*`);
  const fields = await redis('HGETALL', bucket);
  assert.equal(fields[fields.indexOf('c') + 1], '10');
});

await test('429 carries X-RateLimit-* and Retry-After headers; edge cache serves repeats', async () => {
  const id = `headers-${run}`;
  const payload = { identifier: id, action: 'llm_generation', limit: 2, windowSeconds: 30 };
  const a = await rawCheck(apiKey, payload);
  const b = await rawCheck(apiKey, payload);
  const c = await rawCheck(apiKey, payload);
  const d = await rawCheck(apiKey, payload);
  assert.deepEqual([a.status, b.status, c.status, d.status], [200, 200, 429, 429]);
  assert.equal(a.headers.get('x-ratelimit-limit'), '2');
  assert.equal(a.headers.get('x-ratelimit-remaining'), '1');
  assert.equal(c.headers.get('x-ratelimit-remaining'), '0');
  assert.match(c.headers.get('x-ratelimit-reset') ?? '', /^\d{10}$/);
  assert.ok(Number(c.headers.get('retry-after')) >= 1);
  assert.equal(c.body.reason, 'rate_limited');
  assert.equal(d.headers.get('x-ratelimit-cache'), 'HIT');
  assert.equal(d.body.reset, c.body.reset);
});

await test('sliding window: weighted previous window decays and capacity returns', async () => {
  const rl = limiter({ localBlockCache: false });
  const id = `slide-${run}`;
  // Align to the start of a 2s window so the test is deterministic.
  await sleep(2_000 - (Date.now() % 2_000) + 50);
  for (let i = 0; i < 4; i += 1) assert.equal((await rl.check(id, 4, 2)).success, true);
  const denied = await rl.check(id, 4, 2);
  assert.equal(denied.success, false);
  // Wait for capacity per the server's reset and retry.
  await sleep(Math.max(0, denied.reset - Date.now()) + 100);
  assert.equal((await rl.check(id, 4, 2)).success, true);
  // Immediately after, the weighted previous window still applies.
  const after = await rl.check(id, 4, 2);
  assert.equal(after.success, false, 'previous window weight should still block');
});

await test('per-IP bucket stops identifier rotation (credential stuffing)', async () => {
  const rl = limiter({ localBlockCache: false });
  const ip = '198.51.100.23';
  const outcomes = [];
  for (let i = 0; i < 6; i += 1) {
    outcomes.push(await rl.check(`victim-${i}-${run}`, 5, 60, { action: 'login_attempt', ip, ipLimit: 3 }));
  }
  assert.deepEqual(
    outcomes.map((o) => o.success),
    [true, true, true, false, false, false],
  );
  assert.equal(outcomes[3].reason, 'ip_rate_limited');
});

await test('IPv6 addresses in the same /64 share one bucket; IPv4-mapped equals IPv4', async () => {
  const rl = limiter({ localBlockCache: false });
  const opts = (ip) => ({ action: `v6-${run}`, ip, ipLimit: 2 });
  assert.ok((await rl.check('a', 100, 60, opts('2001:db8:1:2::1'))).success);
  assert.ok((await rl.check('b', 100, 60, opts('2001:db8:1:2:ffff:ffff:ffff:fffe'))).success);
  const third = await rl.check('c', 100, 60, opts('2001:db8:1:2:abcd::9'));
  assert.equal(third.reason, 'ip_rate_limited');
  assert.ok((await rl.check('d', 100, 60, opts('2001:db8:1:3::1'))).success, 'different /64 is separate');

  assert.ok((await rl.check('e', 100, 60, opts('192.0.2.1'))).success);
  assert.ok((await rl.check('f', 100, 60, opts('::ffff:192.0.2.1'))).success);
  assert.equal((await rl.check('g', 100, 60, opts('::ffff:c000:201'))).reason, 'ip_rate_limited');
});

await test('Redis keys never contain identifiers or IPs in clear text', async () => {
  const keys = await redis('KEYS', `rl:{${tenant}:*`);
  assert.ok(keys.length > 0);
  for (const k of keys) {
    assert.match(k, /^rl:\{e2e-[^}]+\}:w\d+:(id|ip):[0-9a-f]{64}$/);
    assert.ok(!k.includes('198.51.100.23') && !k.includes('victim'));
  }
});

await test('validation: unknown fields, bad IPs and wrong content-type are rejected', async () => {
  const bad = await rawCheck(apiKey, { identifier: 'x', limit: 1, windowSeconds: 1, admin: true });
  assert.equal(bad.status, 400);
  assert.ok(bad.body.details.includes('unknown field: admin'));
  const badIp = await rawCheck(apiKey, { identifier: 'x', limit: 1, windowSeconds: 1, ip: '999.1.1.1' });
  assert.equal(badIp.status, 400);
  const res = await fetch(`${BASE}/v1/check`, {
    method: 'POST',
    headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'text/plain' },
    body: '{}',
  });
  assert.equal(res.status, 415);
  const big = await rawCheck(apiKey, { identifier: 'x'.repeat(5000), limit: 1, windowSeconds: 1 });
  assert.equal(big.status, 413);
});

await test('invalid / malformed keys get a generic 401 and the SDK throws (no retry)', async () => {
  const fake = `rlk_${'B'.repeat(43)}00000000`;
  const raw = await rawCheck(fake, { identifier: 'x', limit: 1, windowSeconds: 1 });
  assert.equal(raw.status, 401);
  assert.equal(raw.body.error, 'invalid_api_key');
  // A syntactically valid key with correct checksum that does not exist:
  const created2 = await admin('POST', `/tenants/${tenant}-tmp/keys`, {});
  await admin('DELETE', `/keys/${created2.body.key.keyId}`);
  const rl = new RateLimiter(created2.body.apiKey, { baseUrl: BASE });
  await assert.rejects(rl.check('x', 1, 1), (e) => e instanceof RateLimiterHttpError && e.status === 401);
});

await test('fail-open: Redis slower than REDIS_TIMEOUT_MS → request allowed, flagged', async () => {
  await faults(REDIS_TIMEOUT_MS + 400, null);
  try {
    const started = performance.now();
    const raw = await rawCheck(apiKey, { identifier: `slow-${run}`, limit: 1, windowSeconds: 60 });
    const elapsed = performance.now() - started;
    assert.equal(raw.status, 200);
    assert.equal(raw.body.reason, 'fail_open');
    assert.equal(raw.headers.get('x-ratelimit-fail-open'), 'true');
    assert.ok(elapsed < REDIS_TIMEOUT_MS + 300, `fail-open took ${Math.round(elapsed)}ms`);
  } finally {
    await faults(0, null);
  }
});

await test('fail-open: Redis returning 503 → request allowed', async () => {
  await faults(0, 503);
  try {
    const out = await limiter({ localBlockCache: false }).check(`down-${run}`, 1, 60);
    assert.equal(out.success, true);
    assert.equal(out.reason, 'fail_open');
  } finally {
    await faults(0, null);
  }
});

await test('SDK fails open when the edge API itself is unreachable', async () => {
  const events = [];
  const rl = new RateLimiter(apiKey, {
    baseUrl: 'http://127.0.0.1:9', // nothing listens here
    backoffBaseMs: 5,
    onFailOpen: (e) => events.push(e.attempts),
  });
  const out = await rl.check('x', 5, 60);
  assert.equal(out.reason, 'fail_open');
  assert.deepEqual(events, [3]);
});

await test('zero-downtime rotation: both keys valid during grace, old key dies after', async () => {
  const rotated = await admin('POST', `/keys/${keyId}/rotate`, { gracePeriodSeconds: 2, label: 'rotated' });
  assert.equal(rotated.status, 201, JSON.stringify(rotated.body));
  const newKey = rotated.body.apiKey;
  assert.notEqual(newKey, apiKey);
  assert.ok(rotated.body.previous.expiresAt > Date.now());

  const oldRl = new RateLimiter(apiKey, { baseUrl: BASE });
  const newRl = new RateLimiter(newKey, { baseUrl: BASE });
  assert.ok((await oldRl.check(`rot-${run}`, 100, 60)).success, 'old key valid during grace');
  assert.ok((await newRl.check(`rot-${run}`, 100, 60)).success, 'new key valid immediately');

  await sleep(2_300);
  await assert.rejects(oldRl.check(`rot-${run}`, 100, 60), (e) => e instanceof RateLimiterHttpError && e.status === 401);
  assert.ok((await newRl.check(`rot-${run}`, 100, 60)).success);

  // Rotating an already-expired key is refused.
  const again = await admin('POST', `/keys/${keyId}/rotate`, { gracePeriodSeconds: 0 });
  assert.equal(again.status, 409);
  process.env.E2E_ROTATED_KEY = newKey;
});

await test('emergency revocation (leaked key) takes effect immediately', async () => {
  const fresh = await admin('POST', `/tenants/${tenant}/keys`, { label: 'to-revoke' });
  const rl = new RateLimiter(fresh.body.apiKey, { baseUrl: BASE });
  assert.ok((await rl.check(`rev-${run}`, 10, 60)).success);
  const revoked = await admin('DELETE', `/keys/${fresh.body.key.keyId}`);
  assert.equal(revoked.status, 200);
  await assert.rejects(rl.check(`rev-${run}`, 10, 60), (e) => e instanceof RateLimiterHttpError && e.status === 401);
});

await test('key listing exposes metadata only (hash prefix, never key material)', async () => {
  const listed = await admin('GET', `/tenants/${tenant}/keys`);
  assert.equal(listed.status, 200);
  assert.ok(listed.body.keys.length >= 3);
  const text = JSON.stringify(listed.body);
  assert.ok(!text.includes(apiKey) && !/rlk_/.test(text));
  for (const k of listed.body.keys) assert.match(k.keyHashPrefix, /^[0-9a-f]{12}$/);
});

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
if (process.env.E2E_EXPORT_KEY_FILE) {
  const { writeFileSync } = await import('node:fs');
  writeFileSync(process.env.E2E_EXPORT_KEY_FILE, process.env.E2E_ROTATED_KEY ?? '');
}
process.exit(failed.length === 0 ? 0 : 1);
