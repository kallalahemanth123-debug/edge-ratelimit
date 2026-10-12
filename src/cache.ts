/**
 * Bounded, TTL-aware LRU cache living in isolate memory.
 *
 * Workers isolates are reused across many requests, so module-scope caches
 * absorb repeated lookups (API keys, active blocks) without a Redis round trip.
 * The size bound keeps a flood of unique keys from exhausting the 128 MB
 * isolate memory limit.
 */
export class TtlLruCache<V> {
  private readonly entries = new Map<string, { value: V; expiresAt: number }>();
  private readonly maxEntries: number;
  private readonly now: () => number;

  constructor(maxEntries: number, now: () => number = () => Date.now()) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new RangeError('maxEntries must be a positive integer');
    }
    this.maxEntries = maxEntries;
    this.now = now;
  }

  get(key: string): V | undefined {
    const entry = this.entries.get(key);
    if (entry === undefined) {
      return undefined;
    }
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return undefined;
    }
    // Refresh recency: Map preserves insertion order, so re-insert at the tail.
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }

  /** Returns the remaining lifetime in ms, or null when absent/expired. */
  remainingTtl(key: string): number | null {
    const entry = this.entries.get(key);
    if (entry === undefined) {
      return null;
    }
    const remaining = entry.expiresAt - this.now();
    if (remaining <= 0) {
      this.entries.delete(key);
      return null;
    }
    return remaining;
  }

  set(key: string, value: V, ttlMs: number): void {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      this.entries.delete(key);
      return;
    }
    this.entries.delete(key);
    this.entries.set(key, { value, expiresAt: this.now() + ttlMs });
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done === true) {
        break;
      }
      this.entries.delete(oldest.value);
    }
  }

  delete(key: string): void {
    this.entries.delete(key);
  }

  clear(): void {
    this.entries.clear();
  }

  get size(): number {
    return this.entries.size;
  }
}
