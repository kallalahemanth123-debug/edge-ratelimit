/**
 * Key management API (create / rotate / revoke / list).
 *
 * Protected by ADMIN_API_TOKEN, compared in constant time. When the token is
 * not configured the entire surface returns 404, so it is opt-in. In a larger
 * deployment this would live in a separate Worker behind Cloudflare Access.
 */

import { Hono } from 'hono';
import {
  KeyManagementError,
  MAX_GRACE_SECONDS,
  MAX_KEY_LIFETIME_SECONDS,
  MAX_LABEL_LENGTH,
  TENANT_ID_PATTERN,
} from './apikeys';
import { type AppContext, type AppEnv, jsonError } from './context';
import { KEY_ID_PATTERN, secretsEqual } from './crypto';
import { errorFields } from './logger';
import { RedisUnavailableError } from './redis';

export const admin = new Hono<AppEnv>();

admin.use('*', async (c, next) => {
  const expected = c.get('config').adminToken;
  if (expected === null) {
    return jsonError(c, 404, 'not_found', 'Not found');
  }
  const header = c.req.header('authorization') ?? '';
  const presented = header.startsWith('Bearer ') ? header.slice('Bearer '.length).trim() : '';
  // Always hash-and-compare (even for empty input) so timing reveals nothing.
  const valid = await secretsEqual(presented, expected);
  if (!valid || presented.length === 0) {
    c.get('logger').warn('admin.auth_failed', { path: c.req.path });
    c.header('WWW-Authenticate', 'Bearer realm="admin"');
    return jsonError(c, 401, 'unauthorized', 'Invalid admin credentials');
  }
  await next();
  return undefined;
});

async function readJsonObject(c: AppContext): Promise<Record<string, unknown> | null> {
  const raw = await c.req.text();
  if (raw.trim() === '') {
    return {};
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function readLabel(body: Record<string, unknown>, errors: string[]): string | null {
  const label = body['label'];
  if (label === undefined || label === null) {
    return null;
  }
  if (typeof label !== 'string' || label.length > MAX_LABEL_LENGTH || /[\u0000-\u001f]/.test(label)) {
    errors.push(`label must be a printable string of at most ${MAX_LABEL_LENGTH} characters`);
    return null;
  }
  return label;
}

function readOptionalSeconds(
  body: Record<string, unknown>,
  field: string,
  min: number,
  max: number,
  errors: string[],
): number | null {
  const value = body[field];
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) {
    errors.push(`${field} must be an integer between ${min} and ${max}`);
    return null;
  }
  return value;
}

function rejectUnknownFields(body: Record<string, unknown>, allowed: readonly string[], errors: string[]): void {
  for (const key of Object.keys(body)) {
    if (!allowed.includes(key)) {
      errors.push(`unknown field: ${key.slice(0, 64)}`);
    }
  }
}

function handleAdminError(c: AppContext, error: unknown): Response {
  if (error instanceof KeyManagementError) {
    const status = error.code === 'not_found' ? 404 : 409;
    return jsonError(c, status, error.code, error.message);
  }
  if (error instanceof RedisUnavailableError) {
    c.get('logger').error('admin.redis_unavailable', errorFields(error));
    return jsonError(c, 503, 'store_unavailable', 'Key store temporarily unavailable; retry later');
  }
  c.get('logger').error('admin.unexpected_error', errorFields(error));
  return jsonError(c, 500, 'internal_error', 'Unexpected error');
}

// POST /v1/admin/tenants/:tenantId/keys  { label?, expiresInSeconds? }
admin.post('/tenants/:tenantId/keys', async (c) => {
  const tenantId = c.req.param('tenantId');
  if (!TENANT_ID_PATTERN.test(tenantId)) {
    return jsonError(c, 400, 'invalid_request', 'tenantId must match ^[A-Za-z0-9_-]{1,64}$');
  }
  const body = await readJsonObject(c);
  if (body === null) {
    return jsonError(c, 400, 'invalid_json', 'Body must be a JSON object');
  }
  const errors: string[] = [];
  rejectUnknownFields(body, ['label', 'expiresInSeconds'], errors);
  const label = readLabel(body, errors) ?? '';
  const expiresIn = readOptionalSeconds(body, 'expiresInSeconds', 60, MAX_KEY_LIFETIME_SECONDS, errors);
  if (errors.length > 0) {
    return jsonError(c, 400, 'invalid_request', 'Request validation failed', errors);
  }
  try {
    const issued = await c.get('services').keys.createKey(tenantId, label, expiresIn);
    c.get('logger').info('admin.key_created', {
      tenantId,
      keyId: issued.record.keyId,
      keyHashPrefix: issued.record.keyHashPrefix,
    });
    c.header('Cache-Control', 'no-store');
    return c.json({ apiKey: issued.apiKey, key: issued.record }, 201);
  } catch (error: unknown) {
    return handleAdminError(c, error);
  }
});

// GET /v1/admin/tenants/:tenantId/keys
admin.get('/tenants/:tenantId/keys', async (c) => {
  const tenantId = c.req.param('tenantId');
  if (!TENANT_ID_PATTERN.test(tenantId)) {
    return jsonError(c, 400, 'invalid_request', 'tenantId must match ^[A-Za-z0-9_-]{1,64}$');
  }
  try {
    const keys = await c.get('services').keys.listKeys(tenantId);
    return c.json({ tenantId, keys });
  } catch (error: unknown) {
    return handleAdminError(c, error);
  }
});

// POST /v1/admin/keys/:keyId/rotate  { gracePeriodSeconds, label? }
admin.post('/keys/:keyId/rotate', async (c) => {
  const keyId = c.req.param('keyId');
  if (!KEY_ID_PATTERN.test(keyId)) {
    return jsonError(c, 400, 'invalid_request', 'Malformed keyId');
  }
  const body = await readJsonObject(c);
  if (body === null) {
    return jsonError(c, 400, 'invalid_json', 'Body must be a JSON object');
  }
  const errors: string[] = [];
  rejectUnknownFields(body, ['gracePeriodSeconds', 'label'], errors);
  const grace = readOptionalSeconds(body, 'gracePeriodSeconds', 0, MAX_GRACE_SECONDS, errors);
  if (grace === null && errors.length === 0) {
    errors.push('gracePeriodSeconds is required (use 0 to revoke the old key immediately)');
  }
  const label = readLabel(body, errors);
  if (errors.length > 0 || grace === null) {
    return jsonError(c, 400, 'invalid_request', 'Request validation failed', errors);
  }
  try {
    const { issued, previous } = await c.get('services').keys.rotateKey(keyId, grace, label);
    c.get('logger').info('admin.key_rotated', {
      tenantId: issued.record.tenantId,
      oldKeyId: previous.keyId,
      newKeyId: issued.record.keyId,
      gracePeriodSeconds: grace,
    });
    c.header('Cache-Control', 'no-store');
    return c.json({ apiKey: issued.apiKey, key: issued.record, previous }, 201);
  } catch (error: unknown) {
    return handleAdminError(c, error);
  }
});

// DELETE /v1/admin/keys/:keyId  → immediate revocation
admin.delete('/keys/:keyId', async (c) => {
  const keyId = c.req.param('keyId');
  if (!KEY_ID_PATTERN.test(keyId)) {
    return jsonError(c, 400, 'invalid_request', 'Malformed keyId');
  }
  try {
    const revoked = await c.get('services').keys.revokeKey(keyId);
    c.get('logger').warn('admin.key_revoked', { tenantId: revoked.tenantId, keyId: revoked.keyId });
    return c.json({ key: revoked });
  } catch (error: unknown) {
    return handleAdminError(c, error);
  }
});
