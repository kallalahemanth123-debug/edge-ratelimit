# Edge Rate Limit & Abuse Protection

[![CI](https://github.com/kallalahemanth123-debug/edge-ratelimit/actions/workflows/ci.yml/badge.svg)](https://github.com/kallalahemanth123-debug/edge-ratelimit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A serverless rate-limiting API: **Cloudflare Workers + Hono** at the edge,
**Upstash Redis** for distributed counters, and drop-in SDKs for
**TypeScript/Node.js** and **Python**.

```
 your API ──SDK──▶ Cloudflare edge (Hono Worker) ──EVALSHA──▶ Upstash Redis
   │  local block cache      │ isolate key + block caches        │ one atomic Lua script:
   │  retries w/ jitter      │ SHA-256 key auth, fail-open        │ sliding window counter,
   │  fail-open              │ 429 + X-RateLimit-* headers        │ Redis clock, multi-bucket
```

- **Algorithm:** Sliding Window Counter, executed atomically in Lua (no race
  conditions — 100 concurrent requests with `limit=10` yield exactly 10 allows).
- **Abuse protection:** optional per-IP bucket alongside the per-identifier
  bucket (stops credential stuffing across usernames); IPv6 limited per /64.
- **Zero trust:** API keys stored only as SHA-256, never logged, constant-time
  admin auth, strict input validation, PII hashed before it reaches Redis.
- **Fail-open:** if Redis is slow (`REDIS_TIMEOUT_MS`) or down, requests are
  allowed, flagged, and logged asynchronously.

Threat analysis (clock drift, thundering herd, key leakage & rotation):
see **[SECURITY.md](SECURITY.md)**.

## Repository layout

| Path | What |
|---|---|
| `src/worker.ts` | Worker entry: Hono app, `/v1/check`, fail-open, headers |
| `src/lua.ts` | Atomic sliding-window script + key create/rotate/revoke scripts |
| `src/ratelimit.ts` | Bucket derivation, decision aggregation, edge block cache |
| `src/apikeys.ts` | Hashed key store, caches, single-flight lookup, rotation |
| `src/redis.ts` | Upstash REST client (timeouts, EVALSHA→EVAL fallback) |
| `src/env.ts` | Typed env validation (fails loudly, never echoes secrets) |
| `src/validation.ts` | Strict request validation, IP canonicalisation |
| `src/admin.ts` | Key management API |
| `src/logger.ts`, `src/cache.ts`, `src/crypto.ts`, `src/context.ts` | Support |
| `sdk/node/` | npm package `@edge-ratelimit/sdk` (ESM, zero deps) |
| `sdk/python/` | PyPI package `edge-ratelimit` (httpx, sync + async) |
| `dev/` | Upstash REST emulator, end-to-end + Lua property tests |

## API

### `POST /v1/check`

```http
Authorization: Bearer rlk_…
Content-Type: application/json

{ "identifier": "user_123", "action": "login_attempt", "limit": 5, "windowSeconds": 60,
  "ip": "203.0.113.9", "ipLimit": 20 }
```

| Field | Rules |
|---|---|
| `identifier` | required, 1–256 chars (hashed before storage) |
| `action` | optional, `^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`, default `default` |
| `limit` | required integer 1–1,000,000 |
| `windowSeconds` | required integer 1–2,592,000 |
| `ip` | optional IPv4/IPv6; enables a second per-IP bucket |
| `ipLimit` | optional (requires `ip`), defaults to `limit` |

Response (`200` allowed / `429` blocked):

```json
{ "success": false, "limit": 5, "remaining": 0, "reset": 1791762320000,
  "isBlocked": true, "reason": "rate_limited" }
```

`reset` is Unix **milliseconds**. `reason` ∈ `rate_limited`, `ip_rate_limited`,
`fail_open`. Headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
`X-RateLimit-Reset` (Unix seconds), `X-RateLimit-Reset-After-Ms`,
`Retry-After` (on 429), `X-RateLimit-Fail-Open`, `X-RateLimit-Cache`,
`X-Request-Id`. Errors: `400` validation, `401` bad key, `413`, `415`.

### Admin (enabled only when `ADMIN_API_TOKEN` is set)

| Method & path | Body | |
|---|---|---|
| `POST /v1/admin/tenants/:tenantId/keys` | `{ label?, expiresInSeconds? }` | issue a key (plaintext returned once) |
| `GET /v1/admin/tenants/:tenantId/keys` | — | list metadata (no key material) |
| `POST /v1/admin/keys/:keyId/rotate` | `{ gracePeriodSeconds, label? }` | zero-downtime rotation |
| `DELETE /v1/admin/keys/:keyId` | — | immediate revocation |

## Configuration

| Variable | Required | Default | Notes |
|---|---|---|---|
| `UPSTASH_REDIS_REST_URL` | yes | — | https (http only for localhost in development) |
| `UPSTASH_REDIS_REST_TOKEN` | yes | — | secret |
| `ADMIN_API_TOKEN` | no | — | ≥ 32 chars; enables `/v1/admin` |
| `REDIS_TIMEOUT_MS` | no | 250 | 10–5000; beyond this the check fails open |
| `KEY_CACHE_TTL_SECONDS` | no | 30 | 0–300; revocation propagation bound |
| `LOG_DRAIN_URL` / `LOG_DRAIN_TOKEN` | no | — | warn/error shipped via `waitUntil` |
| `ENVIRONMENT` | no | production | production / staging / development |

Validation runs on the first request in each isolate; a bad configuration
returns `500 service_misconfigured` and logs which variables are wrong.

## Deploy

```bash
npm install
npx wrangler secret put UPSTASH_REDIS_REST_URL
npx wrangler secret put UPSTASH_REDIS_REST_TOKEN
npx wrangler secret put ADMIN_API_TOKEN      # e.g. openssl rand -base64 48
npm run deploy

curl -X POST https://<worker>/v1/admin/tenants/acme/keys \
  -H "Authorization: Bearer $ADMIN_API_TOKEN" -H 'content-type: application/json' \
  -d '{"label":"production"}'
```

**Latency note.** Worker execution itself is sub-millisecond; end-to-end time
is dominated by the round trip from the PoP to your Upstash primary region.
Choose the Upstash region closest to your customers' servers. Blocked
subjects are answered from isolate memory (edge) or process memory (SDK)
without any Redis call.

## SDK usage

### TypeScript / Node.js (ESM, Node ≥ 18.17)

```ts
import { RateLimiter } from '@edge-ratelimit/sdk';

const limiter = new RateLimiter(process.env.RATELIMIT_API_KEY!, {
  baseUrl: 'https://rl.example.com',
});

// Express middleware
app.post('/login', async (req, res, next) => {
  const r = await limiter.check(req.body.email, 5, 60, { action: 'login_attempt', ip: req.ip, ipLimit: 20 });
  res.set({ 'X-RateLimit-Limit': String(r.limit), 'X-RateLimit-Remaining': String(r.remaining) });
  if (!r.success) {
    res.set('Retry-After', String(Math.max(1, Math.ceil((r.reset - Date.now()) / 1000))));
    return res.status(429).json({ error: 'Too many attempts' });
  }
  next();
});
```

Options: `timeoutMs` (1000), `maxRetries` (2, max 2), `backoffBaseMs` (100),
`backoffMaxMs` (1000), `failOpen` (true), `localBlockCache` (true),
`defaultAction`, `fetch`, `onFailOpen`.

### Python (3.9+)

```python
from edge_ratelimit import RateLimiter

limiter = RateLimiter(os.environ["RATELIMIT_API_KEY"], base_url="https://rl.example.com")

# FastAPI (async, never blocks the event loop)
@app.post("/generate")
async def generate(request: Request, user=Depends(current_user)):
    r = await limiter.check(user.id, 20, 60, action="llm_generation", ip=request.client.host)
    if not r.success:
        raise HTTPException(429, headers={"Retry-After": str(max(1, (r.reset - int(time.time() * 1000)) // 1000))})
    ...

# Flask (sync WSGI)
@app.post("/login")
def login():
    r = limiter.check_sync(request.form["email"], 5, 60, action="login_attempt", ip=request.remote_addr)
    if not r.success:
        abort(429)
    ...
```

## Local development & tests

CI (`.github/workflows/ci.yml`) runs everything below on every push and pull
request: worker type check, unit tests and production bundle; Node SDK tests on
Node 22/24 plus a runtime smoke test of the built package on Node 18/20; Python
SDK tests on 3.9/3.11/3.13 with `mypy --strict`; and the full end-to-end suite
against workerd and a real Redis (`dev/ci-e2e.sh`).

```bash
# Unit tests + strict type checks
npm test && npm run typecheck
(cd sdk/node && npm install && npm test && npm run typecheck && npm run build && npm run test:smoke)
(cd sdk/python && pip install -e '.[dev]' && pytest && mypy --strict)

# Everything end-to-end in one command (needs Redis on 6379, `pip install redis httpx`)
bash dev/ci-e2e.sh

# Full stack locally (real workerd + real Redis)
redis-server --port 6390 --save '' &
pip install redis && python dev/upstash_emulator.py --port 8079 --token dev-token-123456 \
    --redis redis://127.0.0.1:6390/0 &
cp .dev.vars.example .dev.vars      # already points at the local emulator
(cd sdk/node && npm install && npm run build)
npx wrangler dev --port 8787 --var REDIS_TIMEOUT_MS:1500 &   # the Python emulator is slower than Upstash
E2E_REDIS_TIMEOUT_MS=1500 E2E_EXPORT_KEY_FILE=/tmp/rl-key node dev/e2e.mjs
python dev/e2e_python.py /tmp/rl-key
python dev/lua_property_test.py --redis redis://127.0.0.1:6390/0
```

## License

[MIT](LICENSE)
