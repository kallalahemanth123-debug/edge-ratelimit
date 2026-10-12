#!/usr/bin/env python3
"""
End-to-end test of the Python SDK against a running worker.

    python dev/e2e_python.py <api-key-file>

Env: E2E_BASE_URL (default http://127.0.0.1:8787)
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk" / "python"))

from edge_ratelimit import RateLimiter, RateLimiterHttpError  # noqa: E402

BASE = os.environ.get("E2E_BASE_URL", "http://127.0.0.1:8787")


async def concurrent_async(limiter: RateLimiter, run: str) -> None:
    identifier = f"py-race-{run}"
    results = await asyncio.gather(*(limiter.check(identifier, 7, 60, action="llm_generation") for _ in range(60)))
    allowed = sum(1 for r in results if r.success and r.reason != "fail_open")
    fail_open = sum(1 for r in results if r.reason == "fail_open")
    assert fail_open == 0, f"fail_open={fail_open}"
    assert allowed == 7, f"allowed={allowed}"
    print("  ✓ async: 60 concurrent checks → exactly 7 allowed")


def sync_path(limiter: RateLimiter, run: str) -> None:
    # A unique /64 per run, so the per-IP bucket from earlier runs cannot interfere.
    ip = f"2001:db8:{run[:4]}:{run[4:8]}::77"
    outcomes = [limiter.check_sync(f"py-sync-{run}", 3, 60, action="login_attempt", ip=ip) for _ in range(5)]
    assert [o.success for o in outcomes] == [True, True, True, False, False], outcomes
    assert outcomes[3].reason == "rate_limited" and outcomes[3].remaining == 0
    print("  ✓ sync: limit 3 → allow, allow, allow, block, block (+ reason, remaining)")


def invalid_key() -> None:
    bad = RateLimiter("rlk_" + "Z" * 43 + "00000000", base_url=BASE)
    try:
        bad.check_sync("x", 1, 1)
    except RateLimiterHttpError as exc:
        assert exc.status == 401 and exc.code == "invalid_api_key"
        print("  ✓ invalid key → RateLimiterHttpError(401), no retry")
        return
    raise AssertionError("expected RateLimiterHttpError")


def unreachable(api_key: str) -> None:
    events = []
    limiter = RateLimiter(api_key, base_url="http://127.0.0.1:9", backoff_base_ms=5, on_fail_open=events.append)
    result = limiter.check_sync("x", 5, 60)
    assert result.reason == "fail_open" and result.success and [e.attempts for e in events] == [3]
    print("  ✓ unreachable API → fail open after 3 attempts")


async def main() -> None:
    api_key = Path(sys.argv[1]).read_text().strip()
    run = uuid.uuid4().hex[:8]
    print(f"Python SDK E2E against {BASE}")
    async with RateLimiter(api_key, base_url=BASE, local_block_cache=False) as limiter:
        await concurrent_async(limiter, run)
    with RateLimiter(api_key, base_url=BASE) as limiter:
        sync_path(limiter, run)
    invalid_key()
    unreachable(api_key)
    print("all Python E2E checks passed")


if __name__ == "__main__":
    asyncio.run(main())
