/**
 * Cryptographic primitives built only on WebCrypto, so the same code runs in
 * workerd, Node >= 20 and the test runner.
 */

const encoder = new TextEncoder();

const HEX_TABLE: readonly string[] = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) {
    out += HEX_TABLE[byte] ?? '';
  }
  return out;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function sha256Bytes(input: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  return new Uint8Array(digest);
}

export async function sha256Hex(input: string): Promise<string> {
  return bytesToHex(await sha256Bytes(input));
}

export async function sha1Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', encoder.encode(input));
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Constant-time comparison. Callers hash both inputs first so the length is
 * always 32 bytes and the length check leaks nothing.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/** Compare two secrets of arbitrary length without timing side channels. */
export async function secretsEqual(provided: string, expected: string): Promise<boolean> {
  const [left, right] = await Promise.all([sha256Bytes(provided), sha256Bytes(expected)]);
  return timingSafeEqual(left, right);
}

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

const CRC32_TABLE: Uint32Array = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(input: string): number {
  let crc = 0xffffffff;
  for (const byte of encoder.encode(input)) {
    crc = (CRC32_TABLE[(crc ^ byte) & 0xff] ?? 0) ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * API key format: `rlk_` + 43 chars base64url (256 bits of entropy) + 8 hex
 * chars of CRC32 over everything before it.
 *
 * - The fixed prefix makes leaked keys detectable by secret scanners.
 * - The checksum lets the edge reject typos and random brute-force garbage
 *   without touching Redis. It is NOT a security control on its own.
 */
export const API_KEY_PREFIX = 'rlk_';
const API_KEY_BODY_LENGTH = 43;
const API_KEY_PATTERN = /^rlk_[A-Za-z0-9_-]{43}[0-9a-f]{8}$/;

function checksumHex(prefixAndBody: string): string {
  return crc32(prefixAndBody).toString(16).padStart(8, '0');
}

export function generateApiKey(): string {
  const body = bytesToBase64Url(randomBytes(32));
  if (body.length !== API_KEY_BODY_LENGTH) {
    throw new Error('Unexpected API key body length');
  }
  const prefixAndBody = `${API_KEY_PREFIX}${body}`;
  return `${prefixAndBody}${checksumHex(prefixAndBody)}`;
}

export function isWellFormedApiKey(candidate: string): boolean {
  if (!API_KEY_PATTERN.test(candidate)) {
    return false;
  }
  const prefixAndBody = candidate.slice(0, API_KEY_PREFIX.length + API_KEY_BODY_LENGTH);
  const checksum = candidate.slice(API_KEY_PREFIX.length + API_KEY_BODY_LENGTH);
  return checksumHex(prefixAndBody) === checksum;
}

export function generateKeyId(): string {
  return `key_${bytesToBase64Url(randomBytes(12))}`;
}

export const KEY_ID_PATTERN = /^key_[A-Za-z0-9_-]{16}$/;
