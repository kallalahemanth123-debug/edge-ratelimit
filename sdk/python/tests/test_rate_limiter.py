from __future__ import annotations

import asyncio
import json
import time
from typing import Callable, List, Optional

import httpx
import pytest

from edge_ratelimit import (
    FailOpenEvent,
    RateLimiter,
    RateLimiterConfigError,
    RateLimiterHttpError,
    RateLimiterUnavailableError,
    RateLimiterValidationError,
)

KEY = "rlk_" + "A" * 43 + "0123abcd"
BASE = "https://rl.example.com"
FAST = {"backoff_base_ms": 1, "backoff_max_ms": 2}

Handler = Callable[[httpx.Request], httpx.Response]


def decision(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "success": True,
        "limit": 10,
        "remaining": 9,
        "reset": int(time.time() * 1000) + 60_000,
        "isBlocked": False,
    }
    body.update(overrides)
    return body


class Script:
    """Replays scripted responses; the last one repeats."""

    def __init__(self, responses: List[Handler]) -> None:
        self.responses = responses
        self.requests: List[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        handler = self.responses[min(len(self.requests) - 1, len(self.responses) - 1)]
        return handler(request)


def limiter_for(script: Script, **kwargs: object) -> RateLimiter:
    transport = httpx.MockTransport(script)
    return RateLimiter(
        KEY,
        base_url=BASE,
        async_client=httpx.AsyncClient(transport=transport),
        sync_client=httpx.Client(transport=transport),
        **kwargs,  # type: ignore[arg-type]
    )


def ok(body: Optional[dict[str, object]] = None, status: int = 200, headers: Optional[dict[str, str]] = None) -> Handler:
    return lambda _req: httpx.Response(status, json=body if body is not None else decision(), headers=headers)


def fail(status: int) -> Handler:
    return lambda _req: httpx.Response(status, text="boom")


def test_construction_validates_config() -> None:
    with pytest.raises(RateLimiterConfigError):
        RateLimiter("nope", base_url=BASE)
    with pytest.raises(RateLimiterConfigError, match="https"):
        RateLimiter(KEY, base_url="http://rl.example.com")
    with pytest.raises(RateLimiterConfigError, match="max_retries"):
        RateLimiter(KEY, base_url=BASE, max_retries=3)
    RateLimiter(KEY, base_url="http://localhost:8787")
    assert KEY not in repr(RateLimiter(KEY, base_url=BASE))


def test_async_check_sends_payload_and_parses_result() -> None:
    script = Script([ok()])
    limiter = limiter_for(script)
    result = asyncio.run(limiter.check("user-1", 10, 60, action="llm_generation", ip="203.0.113.5", ip_limit=50))
    assert result.success is True and result.remaining == 9 and result.reason is None
    request = script.requests[0]
    assert str(request.url) == f"{BASE}/v1/check"
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert json.loads(request.content) == {
        "identifier": "user-1",
        "action": "llm_generation",
        "limit": 10,
        "windowSeconds": 60,
        "ip": "203.0.113.5",
        "ipLimit": 50,
    }


def test_sync_check_treats_429_as_decision() -> None:
    script = Script([ok(decision(success=False, remaining=0, isBlocked=True, reason="rate_limited"), status=429)])
    result = limiter_for(script).check_sync("u", 10, 60)
    assert result.success is False and result.is_blocked is True and result.reason == "rate_limited"


def test_retries_5xx_then_succeeds_async_and_sync() -> None:
    script = Script([fail(500), fail(503), ok()])
    assert asyncio.run(limiter_for(script, **FAST).check("u", 10, 60)).success
    assert len(script.requests) == 3

    script = Script([fail(502), ok()])
    assert limiter_for(script, **FAST).check_sync("u", 10, 60).success
    assert len(script.requests) == 2


def test_fails_open_after_two_retries() -> None:
    events: List[FailOpenEvent] = []
    script = Script([fail(500)])
    limiter = limiter_for(script, on_fail_open=events.append, **FAST)
    result = limiter.check_sync("u", 10, 60)
    assert result.success is True and result.reason == "fail_open" and result.limit == 10
    assert len(script.requests) == 3
    assert [e.attempts for e in events] == [3]


def test_network_errors_raise_when_fail_open_disabled() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    script = Script([boom])
    with pytest.raises(RateLimiterUnavailableError):
        asyncio.run(limiter_for(script, fail_open=False, **FAST).check("u", 10, 60))
    assert len(script.requests) == 3


def test_timeouts_are_retried() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    script = Script([slow, ok()])
    assert limiter_for(script, **FAST).check_sync("u", 10, 60).success
    assert len(script.requests) == 2


def test_401_is_fatal_and_not_retried() -> None:
    body: dict[str, object] = {
        "error": "invalid_api_key",
        "message": "API key is invalid, expired or revoked",
        "requestId": "r1",
    }
    script = Script([ok(body, status=401)])
    with pytest.raises(RateLimiterHttpError) as info:
        limiter_for(script, **FAST).check_sync("u", 10, 60)
    assert info.value.status == 401 and info.value.code == "invalid_api_key" and info.value.request_id == "r1"
    assert len(script.requests) == 1


def test_malformed_body_is_retried() -> None:
    script = Script([ok({"hello": "world"}), ok()])
    assert limiter_for(script, **FAST).check_sync("u", 10, 60).success
    assert len(script.requests) == 2


def test_local_block_cache_absorbs_floods() -> None:
    blocked = decision(success=False, remaining=0, isBlocked=True, reason="rate_limited")
    script = Script([ok(blocked, status=429, headers={"x-ratelimit-reset-after-ms": "5000"})])
    limiter = limiter_for(script)
    for _ in range(100):
        assert limiter.check_sync("bot", 10, 60).is_blocked
    assert len(script.requests) == 1
    limiter.check_sync("human", 10, 60)
    assert len(script.requests) == 2


def test_validation_happens_before_network() -> None:
    script = Script([ok()])
    limiter = limiter_for(script)
    for args, kwargs in [
        (("", 10, 60), {}),
        (("u", 0, 60), {}),
        (("u", 10, True), {}),
        (("u", 10, 60), {"ip_limit": 5}),
        (("u", 10, 60), {"action": "bad action"}),
    ]:
        with pytest.raises(RateLimiterValidationError):
            limiter.check_sync(*args, **kwargs)  # type: ignore[arg-type]
    assert script.requests == []


def test_async_client_survives_multiple_event_loops(monkeypatch: pytest.MonkeyPatch) -> None:
    """Code that calls asyncio.run() per request must not hit a dead event loop."""
    transport = httpx.MockTransport(lambda _req: httpx.Response(200, json=decision()))
    original = httpx.AsyncClient
    created: List[httpx.AsyncClient] = []

    def factory(**kwargs: object) -> httpx.AsyncClient:
        client = original(transport=transport)
        created.append(client)
        return client

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    limiter = RateLimiter(KEY, base_url=BASE)
    assert asyncio.run(limiter.check("u", 10, 60)).success
    assert asyncio.run(limiter.check("u", 10, 60)).success
    assert len(created) == 2  # one client per loop, rebuilt transparently
