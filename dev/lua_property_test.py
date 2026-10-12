#!/usr/bin/env python3
"""
Randomised property test for the sliding-window Lua script against a real Redis.

For thousands of random (limit, window, prev, curr) states it checks that the
script's decision, `remaining`, stored counters and — for denials — the
`reset` instant all match an independent reference model. For denials it
verifies `reset` is the *earliest* millisecond at which one more request fits.

    pip install redis
    python dev/lua_property_test.py --redis redis://127.0.0.1:6379/0 --cases 3000
"""

from __future__ import annotations

import argparse
import random
import re
from pathlib import Path

import redis

EPS = 1e-9


def load_script() -> str:
    source = (Path(__file__).resolve().parent.parent / "src" / "lua.ts").read_text()
    match = re.search(r"SLIDING_WINDOW_SCRIPT = new LuaScript\(`([\s\S]*?)`\);", source)
    if match is None:
        raise SystemExit("could not find SLIDING_WINDOW_SCRIPT in src/lua.ts")
    return match.group(1)


def estimate(prev: int, curr: int, window: int, window_start: int, t: int) -> float:
    """Reference model: weighted count at absolute time t (ms)."""
    if t < window_start + window:
        return prev * (1 - (t - window_start) / window) + curr
    if t < window_start + 2 * window:
        return curr * (1 - (t - window_start - window) / window)
    return 0.0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--redis", default="redis://127.0.0.1:6379/0")
    parser.add_argument("--cases", type=int, default=3000)
    args = parser.parse_args()

    client = redis.Redis.from_url(args.redis, protocol=2)
    script = client.register_script(load_script())
    checked = denials = 0

    for case in range(args.cases):
        window = random.choice([1_000, 7_000, 60_000, 3_600_000])
        limit = random.randint(1, 20)
        prev = random.randint(0, 25)
        curr = random.randint(0, 25)
        key = f"proptest:{case}"

        seconds, micros = client.time()
        index = (seconds * 1000 + micros // 1000) // window
        client.delete(key)
        client.hset(key, mapping={"w": index, "c": curr, "p": prev})

        allowed, now, _limit, remaining, reset, _ok = (int(x) for x in script(keys=[key], args=[window, 0, limit]))
        if now // window != index:
            client.delete(key)
            continue  # crossed a window boundary between setup and evaluation
        start = index * window
        est = estimate(prev, curr, window, start, now)

        assert allowed == (1 if est + 1 <= limit + EPS else 0), ("decision", case)
        checked += 1
        if allowed:
            assert remaining == max(0, int(limit - (est + 1) + EPS)), ("remaining", case)
            stored = client.hgetall(key)
            assert int(stored[b"c"]) == curr + 1 and int(stored[b"p"]) == prev, ("counters", case)
            client.delete(key)
        else:
            assert remaining == 0 and reset >= now, ("denial shape", case)
            assert estimate(prev, curr, window, start, reset) + 1 <= limit + EPS, ("reset too early", case)
            if reset > now:
                assert estimate(prev, curr, window, start, reset - 1) + 1 > limit - EPS, ("reset not earliest", case)
            denials += 1
            client.delete(key)

    print(f"OK: {checked} cases verified ({denials} denials with exact earliest-retry check)")


if __name__ == "__main__":
    main()
