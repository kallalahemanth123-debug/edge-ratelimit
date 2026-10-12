/**
 * Structured, redacting, non-blocking logger.
 *
 * - Every line is JSON (Workers Logs / Logpush friendly).
 * - Anything that looks like an API key or bearer credential is scrubbed
 *   before it leaves the isolate, as defence in depth: call sites already only
 *   pass key-hash prefixes, never plaintext keys.
 * - warn/error records are optionally shipped to an external drain inside
 *   ctx.waitUntil(), so logging never adds latency to the response.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type LogValue = string | number | boolean | null;
export type LogFields = Readonly<Record<string, LogValue | undefined>>;

const API_KEY_LIKE = /rlk_[A-Za-z0-9_-]{8,}/g;
const BEARER_LIKE = /(bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi;
const MAX_FIELD_LENGTH = 1_000;
const DRAIN_TIMEOUT_MS = 2_000;

export function redact(text: string): string {
  return text.replace(API_KEY_LIKE, 'rlk_[REDACTED]').replace(BEARER_LIKE, '$1[REDACTED]');
}

function sanitize(value: LogValue): LogValue {
  if (typeof value !== 'string') {
    return value;
  }
  const scrubbed = redact(value);
  return scrubbed.length > MAX_FIELD_LENGTH ? `${scrubbed.slice(0, MAX_FIELD_LENGTH)}…` : scrubbed;
}

export function errorFields(error: unknown): Record<string, LogValue> {
  if (error instanceof Error) {
    const fields: Record<string, LogValue> = {
      errorName: error.name,
      errorMessage: error.message,
    };
    if (error.cause instanceof Error) {
      fields['errorCause'] = `${error.cause.name}: ${error.cause.message}`;
    }
    return fields;
  }
  return { errorName: 'NonError', errorMessage: String(error) };
}

export interface LoggerOptions {
  readonly requestId: string;
  readonly environment: string;
  readonly drainUrl: string | null;
  readonly drainToken: string | null;
  readonly waitUntil: (promise: Promise<unknown>) => void;
}

export class Logger {
  private readonly options: LoggerOptions;

  constructor(options: LoggerOptions) {
    this.options = options;
  }

  debug(event: string, fields: LogFields = {}): void {
    this.write('debug', event, fields);
  }

  info(event: string, fields: LogFields = {}): void {
    this.write('info', event, fields);
  }

  warn(event: string, fields: LogFields = {}): void {
    this.write('warn', event, fields);
  }

  error(event: string, fields: LogFields = {}): void {
    this.write('error', event, fields);
  }

  private write(level: LogLevel, event: string, fields: LogFields): void {
    const record: Record<string, LogValue> = {
      ts: new Date().toISOString(),
      level,
      event,
      requestId: this.options.requestId,
      env: this.options.environment,
    };
    for (const [key, value] of Object.entries(fields)) {
      if (value !== undefined) {
        record[key] = sanitize(value);
      }
    }
    const line = redact(JSON.stringify(record));

    switch (level) {
      case 'debug':
        console.debug(line);
        break;
      case 'info':
        console.log(line);
        break;
      case 'warn':
        console.warn(line);
        break;
      case 'error':
        console.error(line);
        break;
    }

    if ((level === 'warn' || level === 'error') && this.options.drainUrl !== null) {
      this.options.waitUntil(this.ship(this.options.drainUrl, line));
    }
  }

  private async ship(url: string, line: string): Promise<void> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DRAIN_TIMEOUT_MS);
    try {
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (this.options.drainToken !== null) {
        headers['authorization'] = `Bearer ${this.options.drainToken}`;
      }
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: line,
        signal: controller.signal,
      });
      await response.body?.cancel();
    } catch {
      // A failing log drain must never affect request handling.
    } finally {
      clearTimeout(timer);
    }
  }
}
