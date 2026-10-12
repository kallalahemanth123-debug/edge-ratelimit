/**
 * Strict request validation. Unknown fields are rejected (zero trust: the
 * edge never silently ignores input it does not understand).
 */

export const LIMITS = Object.freeze({
  identifierMaxLength: 256,
  limitMin: 1,
  limitMax: 1_000_000,
  windowMinSeconds: 1,
  windowMaxSeconds: 2_592_000, // 30 days
  ipMaxLength: 64,
});

export const DEFAULT_ACTION = 'default';
const ACTION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/;
const ALLOWED_FIELDS: ReadonlySet<string> = new Set([
  'identifier',
  'action',
  'ip',
  'limit',
  'windowSeconds',
  'ipLimit',
]);

export interface CheckRequest {
  readonly identifier: string;
  readonly action: string;
  /** Canonical IP subject: dotted IPv4, or an IPv6 /64 prefix. */
  readonly ip: string | null;
  readonly limit: number;
  readonly windowSeconds: number;
  readonly ipLimit: number | null;
}

export type ValidationResult<T> = { ok: true; value: T } | { ok: false; errors: string[] };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readBoundedInteger(
  source: Record<string, unknown>,
  field: string,
  min: number,
  max: number,
  errors: string[],
): number | null {
  const value = source[field];
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    errors.push(`${field} must be an integer`);
    return null;
  }
  if (value < min || value > max) {
    errors.push(`${field} must be between ${min} and ${max}`);
    return null;
  }
  return value;
}

export function parseCheckRequest(body: unknown): ValidationResult<CheckRequest> {
  if (!isPlainObject(body)) {
    return { ok: false, errors: ['body must be a JSON object'] };
  }
  const errors: string[] = [];

  for (const key of Object.keys(body)) {
    if (!ALLOWED_FIELDS.has(key)) {
      errors.push(`unknown field: ${key.slice(0, 64)}`);
    }
  }

  const identifierRaw = body['identifier'];
  let identifier: string | null = null;
  if (typeof identifierRaw !== 'string' || identifierRaw.length === 0) {
    errors.push('identifier must be a non-empty string');
  } else if (identifierRaw.length > LIMITS.identifierMaxLength) {
    errors.push(`identifier must be at most ${LIMITS.identifierMaxLength} characters`);
  } else {
    identifier = identifierRaw;
  }

  let action = DEFAULT_ACTION;
  const actionRaw = body['action'];
  if (actionRaw !== undefined) {
    if (typeof actionRaw !== 'string' || !ACTION_PATTERN.test(actionRaw)) {
      errors.push('action must match ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$');
    } else {
      action = actionRaw;
    }
  }

  let ip: string | null = null;
  const ipRaw = body['ip'];
  if (ipRaw !== undefined && ipRaw !== null) {
    if (typeof ipRaw !== 'string' || ipRaw.length > LIMITS.ipMaxLength) {
      errors.push('ip must be a string');
    } else {
      ip = normalizeIp(ipRaw);
      if (ip === null) {
        errors.push('ip must be a valid IPv4 or IPv6 address');
      }
    }
  }

  const limit = readBoundedInteger(body, 'limit', LIMITS.limitMin, LIMITS.limitMax, errors);
  const windowSeconds = readBoundedInteger(
    body,
    'windowSeconds',
    LIMITS.windowMinSeconds,
    LIMITS.windowMaxSeconds,
    errors,
  );

  let ipLimit: number | null = null;
  if (body['ipLimit'] !== undefined && body['ipLimit'] !== null) {
    ipLimit = readBoundedInteger(body, 'ipLimit', LIMITS.limitMin, LIMITS.limitMax, errors);
    if (ipRaw === undefined || ipRaw === null) {
      errors.push('ipLimit requires ip');
    }
  }

  if (errors.length > 0 || identifier === null || limit === null || windowSeconds === null) {
    return { ok: false, errors: errors.length > 0 ? errors : ['invalid request'] };
  }

  return {
    ok: true,
    value: { identifier, action, ip, limit, windowSeconds, ipLimit },
  };
}

function parseIpv4(input: string): [number, number, number, number] | null {
  const parts = input.split('.');
  if (parts.length !== 4) {
    return null;
  }
  const octets: number[] = [];
  for (const part of parts) {
    // Reject leading zeros ("010") — ambiguous (octal in some parsers).
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) {
      return null;
    }
    const value = Number.parseInt(part, 10);
    if (value > 255) {
      return null;
    }
    octets.push(value);
  }
  const [a, b, c, d] = octets;
  if (a === undefined || b === undefined || c === undefined || d === undefined) {
    return null;
  }
  return [a, b, c, d];
}

function parseHextets(segment: string, allowTrailingIpv4: boolean): number[] | null {
  if (segment === '') {
    return [];
  }
  const groups: number[] = [];
  const parts = segment.split(':');
  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i] ?? '';
    const isLast = i === parts.length - 1;
    if (isLast && allowTrailingIpv4 && part.includes('.')) {
      const v4 = parseIpv4(part);
      if (v4 === null) {
        return null;
      }
      groups.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      continue;
    }
    if (!/^[0-9a-f]{1,4}$/.test(part)) {
      return null;
    }
    groups.push(Number.parseInt(part, 16));
  }
  return groups;
}

function parseIpv6(input: string): number[] | null {
  const doubleColon = input.indexOf('::');
  if (doubleColon !== input.lastIndexOf('::')) {
    return null;
  }
  if (doubleColon === -1) {
    const groups = parseHextets(input, true);
    return groups !== null && groups.length === 8 ? groups : null;
  }
  const head = parseHextets(input.slice(0, doubleColon), false);
  const tail = parseHextets(input.slice(doubleColon + 2), true);
  if (head === null || tail === null) {
    return null;
  }
  const missing = 8 - head.length - tail.length;
  if (missing < 1) {
    return null;
  }
  return [...head, ...new Array<number>(missing).fill(0), ...tail];
}

/**
 * Canonicalise an IP into the subject we rate limit on.
 *
 * - IPv4 → dotted quad.
 * - IPv4-mapped IPv6 (::ffff:a.b.c.d) → the embedded IPv4, so one client
 *   cannot get two buckets by switching notation.
 * - IPv6 → its /64 prefix. A single residential or cloud customer is usually
 *   handed a whole /64, and rotating through 2^64 addresses would otherwise
 *   defeat per-IP limits entirely.
 */
export function normalizeIp(raw: string): string | null {
  let candidate = raw.trim().toLowerCase();
  if (candidate.startsWith('[') && candidate.endsWith(']')) {
    candidate = candidate.slice(1, -1);
  }
  if (candidate.length === 0 || candidate.length > LIMITS.ipMaxLength) {
    return null;
  }
  if (!candidate.includes(':')) {
    const v4 = parseIpv4(candidate);
    return v4 === null ? null : v4.join('.');
  }
  if (candidate.includes('%')) {
    return null; // zone identifiers are link-local only and meaningless here
  }
  const groups = parseIpv6(candidate);
  if (groups === null) {
    return null;
  }
  const isV4Mapped = groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff;
  if (isV4Mapped) {
    const hi = groups[6] ?? 0;
    const lo = groups[7] ?? 0;
    return [hi >> 8, hi & 0xff, lo >> 8, lo & 0xff].join('.');
  }
  return `${groups
    .slice(0, 4)
    .map((g) => g.toString(16))
    .join(':')}::/64`;
}
