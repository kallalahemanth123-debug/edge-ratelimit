import { LuaScript } from './redis';

/**
 * Atomic multi-bucket Sliding Window Counter.
 *
 * Redis executes a Lua script as a single, uninterruptible unit, so 100
 * concurrent requests arriving in the same millisecond are serialised: each
 * one reads the counters, decides, and increments before the next one runs.
 * There is no read-modify-write gap for a race to exploit.
 *
 * Algorithm (per bucket):
 *   estimate = prev_count * ((window - elapsed) / window) + curr_count
 *   allow iff estimate + 1 <= limit
 *
 * Each bucket is ONE hash (declared in KEYS, so it is cluster-safe):
 *   w = index of the window the counters belong to (floor(now / window))
 *   c = count in window w
 *   p = count in window w - 1
 *
 * Time comes from the Redis server clock (TIME), never from the edge node,
 * so every PoP worldwide agrees on window boundaries (see SECURITY.md, clock
 * drift). ARGV[2] (the edge clock) is only a fallback for Redis builds that
 * refuse TIME inside scripts.
 *
 * All buckets must pass for the request to be allowed; a request is counted
 * in every bucket or in none (all-or-nothing). Denied requests perform no
 * writes at all, which keeps the denial path cheap under flood.
 *
 * KEYS[i]          bucket hash key (1..n). All keys share a {hash tag}.
 * ARGV[1]          window length in milliseconds
 * ARGV[2]          fallback "now" in ms (edge clock)
 * ARGV[2 + i]      limit for KEYS[i]
 *
 * Returns { allowed, now_ms, (limit_i, remaining_i, reset_ms_i, ok_i) ... }
 */
export const SLIDING_WINDOW_SCRIPT = new LuaScript(`
if redis.replicate_commands ~= nil then
  pcall(redis.replicate_commands)
end

local window = tonumber(ARGV[1])
if window == nil or window <= 0 then
  return redis.error_reply('ERR invalid window')
end

local now
local time_ok, t = pcall(redis.call, 'TIME')
if time_ok and type(t) == 'table' and t[1] ~= nil and t[2] ~= nil then
  now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
else
  now = tonumber(ARGV[2])
end
if now == nil then
  return redis.error_reply('ERR clock unavailable')
end

local window_index = math.floor(now / window)
local window_start = window_index * window
local window_end = window_start + window
local elapsed = now - window_start
local weight = (window - elapsed) / window
local EPSILON = 1e-9
local EPSILON_MS = 1e-6 -- absorbs float noise so ceil() does not overshoot by 1ms

-- Earliest instant t >= now at which estimate(t) + 1 <= limit.
local function next_allowed_at(prev, curr, limit)
  local budget = limit - 1
  local at
  if curr <= budget then
    if prev <= 0 then
      return now
    end
    local frac = 1 - (budget - curr) / prev
    if frac < 0 then frac = 0 end
    at = window_start + math.ceil(window * frac - EPSILON_MS)
  else
    -- Needs a rollover: in the next window prev' = curr and curr' = 0.
    local frac = 1 - budget / curr
    at = window_end + math.ceil(window * frac - EPSILON_MS)
  end
  if at < now then at = now end
  return at
end

local n = #KEYS
local states = {}
local allowed = 1

for i = 1, n do
  local limit = tonumber(ARGV[2 + i])
  if limit == nil or limit < 1 then
    return redis.error_reply('ERR invalid limit')
  end
  local raw = redis.call('HMGET', KEYS[i], 'w', 'c', 'p')
  local stored_window = tonumber(raw[1])
  local stored_curr = tonumber(raw[2]) or 0
  local stored_prev = tonumber(raw[3]) or 0
  local prev = 0
  local curr = 0
  if stored_window == window_index then
    prev = stored_prev
    curr = stored_curr
  elseif stored_window == window_index - 1 then
    prev = stored_curr
  end
  local estimate = prev * weight + curr
  local ok = (estimate + 1) <= (limit + EPSILON)
  if not ok then
    allowed = 0
  end
  states[i] = { limit = limit, prev = prev, curr = curr, estimate = estimate, ok = ok }
end

-- Keep a bucket until its current window has fully decayed out of "prev".
local ttl = (window_end + window) - now
local result = { allowed, now }

for i = 1, n do
  local s = states[i]
  local remaining
  local reset
  if allowed == 1 then
    local new_curr = s.curr + 1
    redis.call('HSET', KEYS[i], 'w', window_index, 'c', new_curr, 'p', s.prev)
    redis.call('PEXPIRE', KEYS[i], ttl)
    remaining = math.floor(s.limit - (s.estimate + 1) + EPSILON)
    if remaining < 0 then remaining = 0 end
    if remaining > 0 then
      reset = window_end
    else
      reset = next_allowed_at(s.prev, new_curr, s.limit)
    end
  else
    remaining = math.floor(s.limit - s.estimate + EPSILON)
    if remaining < 0 then remaining = 0 end
    if s.ok then
      reset = window_end
    else
      remaining = 0
      reset = next_allowed_at(s.prev, s.curr, s.limit)
    end
  end
  result[#result + 1] = s.limit
  result[#result + 1] = remaining
  result[#result + 1] = reset
  result[#result + 1] = s.ok and 1 or 0
end

return result
`);

/**
 * Atomic API key rotation.
 *
 * Issues the new key and schedules the old key's expiry in ONE step, so there
 * is never a moment where the tenant has zero valid keys (no downtime) and
 * never a moment where a revoked key is "half rotated".
 *
 * KEYS[1] ak:<old hash>   KEYS[2] ak:<new hash>
 * KEYS[3] akid:<new id>   KEYS[4] tk:<tenant>
 * ARGV: new_key_id, new_hash, tenant_id, label, created_at_ms,
 *       new_expires_at_ms (0 = never), old_grace_ms, now_ms, old_key_id
 *
 * Returns 'OK' | 'NOT_FOUND' | 'NOT_ACTIVE' | 'EXPIRED' | 'TENANT_MISMATCH' | 'COLLISION'
 */
export const ROTATE_KEY_SCRIPT = new LuaScript(`
local old = redis.call('HMGET', KEYS[1], 'status', 'tenantId', 'expiresAt')
if not old[1] then
  return 'NOT_FOUND'
end
if old[1] ~= 'active' then
  return 'NOT_ACTIVE'
end
if old[2] ~= ARGV[3] then
  return 'TENANT_MISMATCH'
end
local now = tonumber(ARGV[8])
local old_expires = tonumber(old[3]) or 0
if old_expires > 0 and old_expires <= now then
  return 'EXPIRED'
end
if redis.call('EXISTS', KEYS[2]) == 1 or redis.call('EXISTS', KEYS[3]) == 1 then
  return 'COLLISION'
end

redis.call('HSET', KEYS[2],
  'keyId', ARGV[1],
  'tenantId', ARGV[3],
  'status', 'active',
  'label', ARGV[4],
  'createdAt', ARGV[5],
  'expiresAt', ARGV[6],
  'rotatedFrom', ARGV[9])
redis.call('SET', KEYS[3], ARGV[2])
redis.call('SADD', KEYS[4], ARGV[1])

local grace = tonumber(ARGV[7])
if grace <= 0 then
  redis.call('HSET', KEYS[1], 'status', 'revoked', 'revokedAt', ARGV[8])
else
  local new_old_expiry = now + grace
  if old_expires == 0 or new_old_expiry < old_expires then
    redis.call('HSET', KEYS[1], 'expiresAt', new_old_expiry)
  end
end
return 'OK'
`);

/**
 * Atomic key creation that refuses to overwrite an existing record.
 *
 * KEYS[1] ak:<hash>  KEYS[2] akid:<id>  KEYS[3] tk:<tenant>
 * ARGV: key_id, hash, tenant_id, label, created_at_ms, expires_at_ms
 */
export const CREATE_KEY_SCRIPT = new LuaScript(`
if redis.call('EXISTS', KEYS[1]) == 1 or redis.call('EXISTS', KEYS[2]) == 1 then
  return 'COLLISION'
end
redis.call('HSET', KEYS[1],
  'keyId', ARGV[1],
  'tenantId', ARGV[3],
  'status', 'active',
  'label', ARGV[4],
  'createdAt', ARGV[5],
  'expiresAt', ARGV[6])
redis.call('SET', KEYS[2], ARGV[2])
redis.call('SADD', KEYS[3], ARGV[1])
return 'OK'
`);

/**
 * Atomic revocation (only touches records that exist).
 * KEYS[1] ak:<hash>   ARGV[1] now_ms
 */
export const REVOKE_KEY_SCRIPT = new LuaScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 'NOT_FOUND'
end
redis.call('HSET', KEYS[1], 'status', 'revoked', 'revokedAt', ARGV[1])
return 'OK'
`);
