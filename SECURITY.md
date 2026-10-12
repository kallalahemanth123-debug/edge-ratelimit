# Security & Failure-Mode Analysis (Phase 4)

This document explains how the codebase behaves under three specific threats —
clock drift, thundering herds, and API key leakage — and points to the exact
code that implements each defence. Everything described here is exercised by
the test suites (`test/`, `sdk/*/test*`, `dev/e2e.mjs`, `dev/e2e_python.py`).

---

## 1. Clock drift across distributed edge nodes

**Threat.** A sliding window is only as accurate as the clock that places a
request in a window. Cloudflare runs this Worker in 300+ PoPs; if each PoP used
its own clock, two PoPs a few hundred milliseconds apart would disagree about
which window a request belongs to, double-count or under-count at boundaries,
and hand out inconsistent `reset` times. Inside workerd the problem is worse:
`Date.now()` is deliberately coarse and frozen during execution (a Spectre
mitigation), so it is not a trustworthy timestamp source.

**How the code handles it.**

| Mechanism | Where | Effect |
|---|---|---|
| **One clock: Redis `TIME`** | `SLIDING_WINDOW_SCRIPT` in `src/lua.ts` | The Lua script reads the Redis server clock *inside* the atomic script. Every PoP worldwide computes `window_index = floor(now / window)` from the same clock, so window boundaries are identical everywhere. The edge clock (`ARGV[2]`) is used only if a Redis build refuses `TIME` in scripts. |
| **Single writer** | Upstash topology | `EVAL`/`EVALSHA` is a write, so it always executes on the database's primary. Read replicas (Upstash Global) never serve counters, so there is exactly one authoritative clock and one authoritative counter. |
| **Window identity stored with the counts** | hash fields `w`, `c`, `p` | Each bucket records *which* window its counts belong to. The script recognises stale state (`w < index - 1`) and treats it as empty, so correctness never depends on TTL expiry firing on time — TTLs are only garbage collection. |
| **Durations, never timestamps, cross machine boundaries** | `rememberBlock()` in `src/ratelimit.ts`; `X-RateLimit-Reset-After-Ms` header; `LocalBlockCache` in both SDKs | The worker computes `resetAfterMs = reset − redisNow` (a duration on the Redis clock) and anchors it to its *own* clock when caching a block. The SDKs read the same duration from `X-RateLimit-Reset-After-Ms` and store it against a **monotonic** clock (`performance.now()` / `time.monotonic()`), so a customer server whose wall clock is minutes off — or that receives an NTP step mid-block — still releases the block at the right moment. |
| **Exact earliest-retry time** | `next_allowed_at()` in the Lua script | For a denied request the script solves for the first instant the weighted estimate drops enough to admit one more request, including across a window rollover. `reset` / `Retry-After` therefore point at the real moment capacity returns rather than a guessed window edge. Verified by a 3,000-case randomized property test against real Redis. |

**Residual risk.** If Upstash fails over to a replica whose clock differs by a
few milliseconds (NTP-disciplined hosts), windows shift by that amount once.
That is far below the 1-second minimum window and cannot be exploited by a
client. API-key *expiry* is checked against the edge clock; drift of seconds is
irrelevant against grace periods measured in minutes or hours.

---

## 2. Thundering herd: a blocked client firing thousands of requests

**Threat.** Once an attacker is blocked, every additional request still costs
a Redis round trip in a naive design. A bot sending 10,000 req/s becomes
10,000 Redis commands/s — overloading the database (and the bill) precisely
when the system is under attack. Retrying clients make it worse when the
service hiccups: synchronized retries arrive as a wave.

**How the code handles it — six layers, outermost first.**

1. **SDK local block cache (customer host).** When the API answers "blocked",
   both SDKs cache that decision in-process until the server-reported reset
   (bounded LRU, 10k entries, monotonic TTL). A bot hammering the customer's
   login route triggers **one** network call per block period; the other 9,999
   are answered in microseconds without leaving the host.
   *Code:* `LocalBlockCache` (Node), `_LocalBlockCache` (Python).
   *Test:* "serves repeated blocked checks from the local cache" — 100 checks, 1 request.

2. **Edge isolate block cache (Cloudflare PoP).** Even callers that bypass the
   SDK are absorbed at the edge: denials are cached in isolate memory and
   served with `X-RateLimit-Cache: HIT` without touching Redis. The cache trusts
   a block for at most 60 s (`MAX_BLOCK_CACHE_MS`) before re-confirming, so a
   blocked subject costs roughly **one Redis call per isolate per minute**,
   whatever the request rate. *Code:* `lookupCachedBlock()` / `rememberBlock()`.

3. **Read-only denial path in Redis.** When a request *does* reach Redis and is
   denied, the Lua script performs only `HMGET` — no `HSET`, no `PEXPIRE`, no
   replication traffic. Rejected requests are not counted, so floods do not
   cause write amplification.

4. **O(1) state per subject.** Each bucket is one hash with three integer
   fields. A Sliding *Log* (a ZSET entry per request) would let a flood grow
   memory linearly; the Sliding Window *Counter* cannot be inflated.

5. **Authentication never stampedes.**
   - Keys carry a CRC32 checksum, so random or mistyped keys are rejected at the
     edge with zero Redis traffic (`isWellFormedApiKey`).
   - Valid-format-but-unknown keys are negative-cached; known keys are
     positive-cached (`KEY_CACHE_TTL_SECONDS`, default 30 s).
   - **Single-flight coalescing:** 100 concurrent requests presenting the same
     uncached key share one `HGETALL` (`loadCoalesced()`).

6. **Retry discipline + hard timeouts.**
   - SDKs retry only on 5xx / network errors / timeouts, at most **2** times,
     with exponential backoff and *equal jitter* (`exp/2 + rand·exp/2`) so
     clients de-synchronise instead of retrying in lockstep. 4xx (bad key,
     bad input) is never retried.
   - The worker aborts any Redis call after `REDIS_TIMEOUT_MS` (default 250 ms)
     and fails open, so a slow database produces fast answers rather than a
     pile-up of open connections.

**Concurrency correctness (the "100 requests in the same millisecond" case).**
The check-and-increment is a single Lua script, which Redis executes
atomically: no other command interleaves between reading the counters and
writing them. `dev/e2e.mjs` fires 100 concurrent checks with `limit = 10` and
asserts that exactly 10 are allowed, 90 are blocked, and the Redis counter
reads exactly 10 (no lost or duplicated increments). Multi-bucket checks
(identifier + IP) are all-or-nothing inside the same script.

---

## 3. Key leakage and zero-downtime rotation

**Threat.** A customer commits a key to GitHub, pastes it in a support ticket,
or a log pipeline captures it. We need to (a) limit what a leak of *our*
storage reveals, (b) detect leaks quickly, and (c) replace a compromised key
without any outage for the customer.

### 3a. Minimising what can leak

- **Only hashes are stored.** The plaintext key exists in exactly two places:
  the admin response that issues it (marked `Cache-Control: no-store`) and the
  `Authorization` header of client requests. The worker computes SHA-256
  before any cache lookup, Redis read, or log line (`ApiKeyStore.authenticate`).
  A full dump of Redis yields only hashes.
- **Why plain SHA-256 is correct here.** Keys contain 256 bits of CSPRNG
  entropy, so brute-forcing a hash is infeasible; slow KDFs (bcrypt/Argon2)
  exist to protect *low-entropy passwords* and would only add edge latency.
  (Optional hardening: switch to HMAC-SHA-256 with a pepper held in a Worker
  secret, so a Redis dump alone is useless even for offline checks.)
- **Logs cannot carry keys.** Call sites log only a 12-hex-char hash prefix;
  the logger additionally scrubs anything matching `rlk_…` or `Bearer …`
  (`redact()` in `src/logger.ts`). The e2e run asserts zero plaintext keys in
  worker logs. Both SDKs override `repr`/messages so keys never appear in
  tracebacks.
- **No oracle.** Malformed, unknown, expired and revoked keys all receive the
  same `401 invalid_api_key`; the specific reason is logged server-side only.
- **Admin surface.** `/v1/admin/*` is disabled (404) unless `ADMIN_API_TOKEN`
  is set; the token is compared in constant time (hash-then-XOR compare).
- **Identifiers are hashed too.** Emails, user IDs and IPs are SHA-256'd before
  becoming Redis keys, so a database leak does not expose end-user PII.

### 3b. Detecting leaks

Keys have a fixed, greppable shape: `rlk_` + 43 base64url chars + 8 hex chars
of CRC32. This is the same design GitHub uses for its tokens: secret scanners
(GitHub secret scanning custom patterns, gitleaks, trufflehog) can match the
regex `rlk_[A-Za-z0-9_-]{43}[0-9a-f]{8}` and validate the checksum offline,
which keeps false positives near zero. Registering the pattern with GitHub's
secret scanning partner program lets GitHub notify you when a key is pushed
to a public repository.

### 3c. Rotation without downtime

Rotation is a single atomic Lua script (`ROTATE_KEY_SCRIPT`): it verifies the
old key is active, writes the new key record, indexes it, and schedules the
old key's expiry — in one step. There is never a moment with zero valid keys
and never a half-rotated state. No schema change, migration, or Redis restart
is involved; reads continue throughout.

**Planned rotation (suspected exposure, routine hygiene):**

```bash
# 1. Issue a successor; the old key stays valid for 1 hour.
curl -X POST https://<worker>/v1/admin/keys/<oldKeyId>/rotate \
  -H "Authorization: Bearer $ADMIN_API_TOKEN" -H 'content-type: application/json' \
  -d '{"gracePeriodSeconds": 3600}'
# → {"apiKey": "rlk_…", "key": {...}, "previous": {"expiresAt": …}}

# 2. Put the new key in the customer's secret manager and roll their deploy.
# 3. Nothing else: the old key expires on schedule.
```

**Confirmed leak (stop it now):**

```bash
# Rotate with no grace — the old key is revoked atomically with issuing the new one:
curl -X POST …/v1/admin/keys/<oldKeyId>/rotate -d '{"gracePeriodSeconds": 0}' …
# …or revoke outright:
curl -X DELETE …/v1/admin/keys/<keyId> -H "Authorization: Bearer $ADMIN_API_TOKEN"
```

**Propagation guarantees.** The isolate that served the admin call drops its
cached copy immediately. Other isolates converge within
`KEY_CACHE_TTL_SECONDS` (default 30 s). Because cached records carry
`expiresAt`, a scheduled grace expiry is enforced *exactly* whenever the grace
period is longer than the cache TTL. For instant global revocation set
`KEY_CACHE_TTL_SECONDS=0` (one extra Redis read per request) — a deliberate
latency/consistency knob.

**Audit trail.** Revoked and expired keys are kept as tombstones
(`status`, `revokedAt`), and successors record `rotatedFrom`, so you can
reconstruct who held which key when. `GET /v1/admin/tenants/:id/keys` lists
metadata and hash prefixes only — never key material.

**Platform secrets.** `ADMIN_API_TOKEN`, `UPSTASH_REDIS_REST_TOKEN` and log
drain tokens are Worker secrets; `wrangler secret put` publishes a new version
without downtime. When resetting the Upstash token, the short window between
the reset and the `secret put` is covered by fail-open: clients keep working,
and the `ratelimit.fail_open` log events (with `redisFailure: "auth"`) make the
gap visible.

---

## Appendix: other decisions worth knowing

- **Fail-open is a trade-off, made visible.** An attacker able to degrade
  Upstash could temporarily bypass limits. Every fail-open response carries
  `reason: "fail_open"` and `X-RateLimit-Fail-Open: true`, and is logged at
  `error` level (shipped via `waitUntil` to `LOG_DRAIN_URL` if set). For
  high-risk actions callers can choose fail-closed per call, e.g.
  `if (r.reason === 'fail_open' && action === 'login_attempt') deny()`, or
  construct the SDK with `failOpen: false` for network failures.
- **IPv6 rotation.** IPv6 subjects are limited per **/64**, so a client cannot
  escape a per-IP limit by cycling through the 2^64 addresses it was assigned.
  IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is unified with plain IPv4.
- **Strict input.** Unknown JSON fields are rejected, bodies are capped at
  4 KB, `Content-Type` must be JSON, and action names are restricted to a
  charset that cannot break Redis key namespacing or hash tags.
- **Cluster safety.** All keys touched by one script share a `{tenant:action}`
  hash tag, so the multi-key script stays valid on clustered Redis.
