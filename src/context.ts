import type { Context } from 'hono';
import { ApiKeyStore } from './apikeys';
import type { Bindings, Config } from './env';
import type { Logger } from './logger';
import { UpstashRestClient } from './redis';

export interface Services {
  readonly redis: UpstashRestClient;
  readonly keys: ApiKeyStore;
}

export type AppEnv = {
  Bindings: Bindings;
  Variables: {
    config: Config;
    services: Services;
    logger: Logger;
    requestId: string;
  };
};

export type AppContext = Context<AppEnv>;

const servicesCache = new WeakMap<Config, Services>();

/** One client + store per validated config per isolate (connection reuse). */
export function getServices(config: Config): Services {
  const cached = servicesCache.get(config);
  if (cached !== undefined) {
    return cached;
  }
  const redis = new UpstashRestClient({
    url: config.redisUrl,
    token: config.redisToken,
    timeoutMs: config.redisTimeoutMs,
  });
  const services: Services = { redis, keys: new ApiKeyStore(redis, config.keyCacheTtlMs) };
  servicesCache.set(config, services);
  return services;
}

/** ctx.waitUntil when running in workerd; a detached promise elsewhere (tests). */
export function backgroundRunner(c: Context): (promise: Promise<unknown>) => void {
  return (promise) => {
    try {
      c.executionCtx.waitUntil(promise);
    } catch {
      void promise.catch(() => undefined);
    }
  };
}

export function jsonError(
  c: AppContext,
  status: 400 | 401 | 403 | 404 | 409 | 413 | 415 | 500 | 503,
  error: string,
  message: string,
  details?: readonly string[],
): Response {
  const body: Record<string, unknown> = { error, message, requestId: c.get('requestId') };
  if (details !== undefined && details.length > 0) {
    body['details'] = details;
  }
  return c.json(body, status);
}
