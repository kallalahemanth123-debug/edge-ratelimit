/**
 * API key store.
 *
 * Plaintext keys exist exactly twice in their lifetime: in the HTTP response
 * that issues them, and in the Authorization header of client requests. They
 * are SHA-256 hashed before any lookup, cache access or log line, and only the
 * hash is persisted. Keys carry 256 bits of entropy, so a fast hash is the
 * right primitive here (a slow KDF only matters for low-entropy passwords).
 *
 * Redis layout:
 *   ak:<sha256>     HASH  keyId, tenantId, status, label, createdAt, expiresAt,
 *                         [revokedAt], [rotatedFrom]
 *   akid:<keyId>    STRING  sha256 of the key (lets admins address keys by id)
 *   tk:<tenantId>   SET     keyIds belonging to the tenant
 */

import { TtlLruCache } from './cache';
import {
  generateApiKey,
  generateKeyId,
  isWellFormedApiKey,
  KEY_ID_PATTERN,
  sha256Hex,
} from './crypto';
import { CREATE_KEY_SCRIPT, REVOKE_KEY_SCRIPT, ROTATE_KEY_SCRIPT } from './lua';
import {
  hashReplyToRecord,
  RedisCommandError,
  RedisUnavailableError,
  type RedisReply,
  type UpstashRestClient,
} from './redis';

export type KeyStatus = 'active' | 'revoked';

export interface ApiKeyRecord {
  readonly keyId: string;
  readonly tenantId: string;
  readonly status: KeyStatus;
  readonly label: string;
  readonly createdAt: number;
  /** Unix ms; null = never expires. */
  readonly expiresAt: number | null;
  readonly revokedAt: number | null;
  readonly rotatedFrom: string | null;
}

export interface ApiKeyMetadata extends ApiKeyRecord {
  /** First 12 hex chars of the key hash — safe to display, useless to an attacker. */
  readonly keyHashPrefix: string;
}

export type AuthFailureReason = 'malformed' | 'unknown' | 'revoked' | 'expired';

export type AuthResult =
  | { readonly ok: true; readonly record: ApiKeyRecord; readonly keyHash: string }
  | { readonly ok: false; readonly reason: AuthFailureReason; readonly keyHash: string | null };

export class KeyManagementError extends Error {
  readonly code: 'not_found' | 'not_active' | 'expired' | 'collision' | 'tenant_mismatch';

  constructor(code: KeyManagementError['code'], message: string) {
    super(message);
    this.name = 'KeyManagementError';
    this.code = code;
  }
}

export const TENANT_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
export const MAX_LABEL_LENGTH = 128;
export const MAX_GRACE_SECONDS = 7 * 24 * 60 * 60;
export const MAX_KEY_LIFETIME_SECONDS = 5 * 365 * 24 * 60 * 60;
const MAX_LISTED_KEYS = 1_000;

// Isolate-scoped caches shared by every request served by this isolate.
const positiveCache = new TtlLruCache<ApiKeyRecord>(10_000);
const negativeCache = new TtlLruCache<'unknown'>(50_000);
const inflight = new Map<string, Promise<ApiKeyRecord | null>>();

const keyRecordKey = (hash: string): string => `ak:${hash}`;
const keyIdKey = (keyId: string): string => `akid:${keyId}`;
const tenantKeysKey = (tenantId: string): string => `tk:${tenantId}`;

function parseTimestamp(raw: string | undefined): number | null {
  if (raw === undefined || raw === '' || raw === '0') {
    return null;
  }
  const value = Number(raw);
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}

export function parseKeyRecord(fields: Record<string, string>): ApiKeyRecord {
  const keyId = fields['keyId'];
  const tenantId = fields['tenantId'];
  const status = fields['status'];
  const createdAt = parseTimestamp(fields['createdAt']);
  if (
    keyId === undefined ||
    tenantId === undefined ||
    (status !== 'active' && status !== 'revoked') ||
    createdAt === null
  ) {
    throw new RedisUnavailableError('protocol', 'Corrupt API key record');
  }
  return {
    keyId,
    tenantId,
    status,
    label: fields['label'] ?? '',
    createdAt,
    expiresAt: parseTimestamp(fields['expiresAt']),
    revokedAt: parseTimestamp(fields['revokedAt']),
    rotatedFrom: fields['rotatedFrom'] !== undefined && fields['rotatedFrom'] !== '' ? fields['rotatedFrom'] : null,
  };
}

function scriptStatus(reply: RedisReply): string {
  if (typeof reply !== 'string') {
    throw new RedisUnavailableError('protocol', 'Key management script returned a non-string');
  }
  return reply;
}

function throwForStatus(status: string): void {
  switch (status) {
    case 'OK':
      return;
    case 'NOT_FOUND':
      throw new KeyManagementError('not_found', 'API key not found');
    case 'NOT_ACTIVE':
      throw new KeyManagementError('not_active', 'API key is not active');
    case 'EXPIRED':
      throw new KeyManagementError('expired', 'API key has already expired');
    case 'COLLISION':
      throw new KeyManagementError('collision', 'Key material collision; retry the request');
    case 'TENANT_MISMATCH':
      throw new KeyManagementError('tenant_mismatch', 'API key belongs to a different tenant');
    default:
      throw new RedisUnavailableError('protocol', `Unexpected key script status: ${status.slice(0, 32)}`);
  }
}

export interface IssuedKey {
  /** Plaintext key. Returned once, never stored, never logged. */
  readonly apiKey: string;
  readonly record: ApiKeyMetadata;
}

export class ApiKeyStore {
  private readonly redis: UpstashRestClient;
  private readonly cacheTtlMs: number;

  constructor(redis: UpstashRestClient, cacheTtlMs: number) {
    this.redis = redis;
    this.cacheTtlMs = cacheTtlMs;
  }

  /**
   * Resolve a presented key. Throws RedisUnavailableError only when a Redis
   * round trip was required and failed; callers decide whether to fail open.
   */
  async authenticate(presentedKey: string, nowMs: number = Date.now()): Promise<AuthResult> {
    // Cheap local rejection: random garbage never reaches Redis.
    if (!isWellFormedApiKey(presentedKey)) {
      return { ok: false, reason: 'malformed', keyHash: null };
    }
    const keyHash = await sha256Hex(presentedKey);

    if (negativeCache.get(keyHash) !== undefined) {
      return { ok: false, reason: 'unknown', keyHash };
    }

    let record = positiveCache.get(keyHash) ?? null;
    if (record === null) {
      record = await this.loadCoalesced(keyHash);
    }
    if (record === null) {
      return { ok: false, reason: 'unknown', keyHash };
    }
    if (record.status === 'revoked') {
      return { ok: false, reason: 'revoked', keyHash };
    }
    if (record.expiresAt !== null && record.expiresAt <= nowMs) {
      return { ok: false, reason: 'expired', keyHash };
    }
    return { ok: true, record, keyHash };
  }

  /** Single-flight: N concurrent requests with the same uncached key share one Redis read. */
  private loadCoalesced(keyHash: string): Promise<ApiKeyRecord | null> {
    const existing = inflight.get(keyHash);
    if (existing !== undefined) {
      return existing;
    }
    const pending = this.load(keyHash).finally(() => {
      inflight.delete(keyHash);
    });
    inflight.set(keyHash, pending);
    return pending;
  }

  private async load(keyHash: string): Promise<ApiKeyRecord | null> {
    const fields = hashReplyToRecord(await this.redis.command(['HGETALL', keyRecordKey(keyHash)]));
    if (fields === null) {
      if (this.cacheTtlMs > 0) {
        negativeCache.set(keyHash, 'unknown', this.cacheTtlMs);
      }
      return null;
    }
    const record = parseKeyRecord(fields);
    if (this.cacheTtlMs > 0) {
      positiveCache.set(keyHash, record, this.cacheTtlMs);
    }
    return record;
  }

  async createKey(
    tenantId: string,
    label: string,
    expiresInSeconds: number | null,
    nowMs: number = Date.now(),
  ): Promise<IssuedKey> {
    const apiKey = generateApiKey();
    const keyHash = await sha256Hex(apiKey);
    const keyId = generateKeyId();
    const expiresAt = expiresInSeconds === null ? 0 : nowMs + expiresInSeconds * 1_000;

    const status = scriptStatus(
      await this.redis.evalScript(
        CREATE_KEY_SCRIPT,
        [keyRecordKey(keyHash), keyIdKey(keyId), tenantKeysKey(tenantId)],
        [keyId, keyHash, tenantId, label, nowMs, expiresAt],
      ),
    );
    throwForStatus(status);
    negativeCache.delete(keyHash);

    return {
      apiKey,
      record: {
        keyId,
        tenantId,
        status: 'active',
        label,
        createdAt: nowMs,
        expiresAt: expiresAt === 0 ? null : expiresAt,
        revokedAt: null,
        rotatedFrom: null,
        keyHashPrefix: keyHash.slice(0, 12),
      },
    };
  }

  /**
   * Zero-downtime rotation: issue a successor and give the old key a grace
   * period (0 = revoke immediately, e.g. for a confirmed leak).
   */
  async rotateKey(
    oldKeyId: string,
    graceSeconds: number,
    label: string | null,
    nowMs: number = Date.now(),
  ): Promise<{ issued: IssuedKey; previous: ApiKeyMetadata }> {
    const old = await this.getByKeyId(oldKeyId);
    if (old === null) {
      throw new KeyManagementError('not_found', 'API key not found');
    }

    const apiKey = generateApiKey();
    const keyHash = await sha256Hex(apiKey);
    const keyId = generateKeyId();
    const newLabel = label ?? old.record.label;
    const graceMs = graceSeconds * 1_000;

    const status = scriptStatus(
      await this.redis.evalScript(
        ROTATE_KEY_SCRIPT,
        [
          keyRecordKey(old.keyHash),
          keyRecordKey(keyHash),
          keyIdKey(keyId),
          tenantKeysKey(old.record.tenantId),
        ],
        [keyId, keyHash, old.record.tenantId, newLabel, nowMs, 0, graceMs, nowMs, old.record.keyId],
      ),
    );
    throwForStatus(status);

    // Drop this isolate's cached copy so the new expiry/revocation applies
    // here immediately; other isolates converge within KEY_CACHE_TTL_SECONDS.
    positiveCache.delete(old.keyHash);
    negativeCache.delete(keyHash);

    const refreshed = await this.getByKeyId(oldKeyId);
    return {
      issued: {
        apiKey,
        record: {
          keyId,
          tenantId: old.record.tenantId,
          status: 'active',
          label: newLabel,
          createdAt: nowMs,
          expiresAt: null,
          revokedAt: null,
          rotatedFrom: old.record.keyId,
          keyHashPrefix: keyHash.slice(0, 12),
        },
      },
      previous: refreshed === null ? { ...old.record, keyHashPrefix: old.keyHash.slice(0, 12) } : refreshed.metadata,
    };
  }

  async revokeKey(keyId: string, nowMs: number = Date.now()): Promise<ApiKeyMetadata> {
    const existing = await this.getByKeyId(keyId);
    if (existing === null) {
      throw new KeyManagementError('not_found', 'API key not found');
    }
    const status = scriptStatus(
      await this.redis.evalScript(REVOKE_KEY_SCRIPT, [keyRecordKey(existing.keyHash)], [nowMs]),
    );
    throwForStatus(status);
    positiveCache.delete(existing.keyHash);
    return {
      ...existing.record,
      status: 'revoked',
      revokedAt: nowMs,
      keyHashPrefix: existing.keyHash.slice(0, 12),
    };
  }

  async listKeys(tenantId: string): Promise<ApiKeyMetadata[]> {
    const membersReply = await this.redis.command(['SMEMBERS', tenantKeysKey(tenantId)]);
    if (!Array.isArray(membersReply)) {
      throw new RedisUnavailableError('protocol', 'SMEMBERS reply is not an array');
    }
    const keyIds = membersReply
      .filter((m): m is string => typeof m === 'string' && KEY_ID_PATTERN.test(m))
      .sort()
      .slice(0, MAX_LISTED_KEYS);
    if (keyIds.length === 0) {
      return [];
    }

    const hashes = await this.redis.pipeline(keyIds.map((id) => ['GET', keyIdKey(id)]));
    const resolved: string[] = [];
    for (const hash of hashes) {
      if (hash instanceof RedisCommandError) {
        throw hash;
      }
      if (typeof hash === 'string') {
        resolved.push(hash);
      }
    }
    if (resolved.length === 0) {
      return [];
    }

    const records = await this.redis.pipeline(resolved.map((hash) => ['HGETALL', keyRecordKey(hash)]));
    const result: ApiKeyMetadata[] = [];
    records.forEach((reply, index) => {
      if (reply instanceof RedisCommandError) {
        throw reply;
      }
      const fields = hashReplyToRecord(reply);
      const hash = resolved[index];
      if (fields !== null && hash !== undefined) {
        result.push({ ...parseKeyRecord(fields), keyHashPrefix: hash.slice(0, 12) });
      }
    });
    return result.sort((a, b) => a.createdAt - b.createdAt);
  }

  private async getByKeyId(
    keyId: string,
  ): Promise<{ keyHash: string; record: ApiKeyRecord; metadata: ApiKeyMetadata } | null> {
    if (!KEY_ID_PATTERN.test(keyId)) {
      return null;
    }
    const hash = await this.redis.command(['GET', keyIdKey(keyId)]);
    if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) {
      return null;
    }
    const fields = hashReplyToRecord(await this.redis.command(['HGETALL', keyRecordKey(hash)]));
    if (fields === null) {
      return null;
    }
    const record = parseKeyRecord(fields);
    return { keyHash: hash, record, metadata: { ...record, keyHashPrefix: hash.slice(0, 12) } };
  }
}

/** Test hook. */
export function clearKeyCaches(): void {
  positiveCache.clear();
  negativeCache.clear();
  inflight.clear();
}
