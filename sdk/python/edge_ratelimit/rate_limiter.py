"""
Python client for the Edge Rate Limit & Abuse Protection API (Python 3.9+).

Mirrors the Node.js SDK: same class, same ``check`` semantics, same retry,
fail-open and local block-cache behaviour.

Async frameworks (FastAPI, Starlette, Quart, aiohttp)::

    limiter = RateLimiter(os.environ["RATELIMIT_API_KEY"], base_url="https://rl.example.com")
    result = await limiter.check(user_id, 10, 60, action="llm_generation", ip=client_ip)

Sync frameworks (Flask, Django, any WSGI app)::

    result = limiter.check_sync(user_id, 10, 60, action="login_attempt", ip=client_ip)

``check`` never blocks the event loop (httpx.AsyncClient + asyncio.sleep).
``check_sync`` uses a pooled httpx.Client and is safe to share across WSGI
worker threads.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Tuple, Type, Union
from urllib.parse import urlsplit

import httpx

__all__ = [
    "SDK_VERSION",
    "FailOpenEvent",
    "RateLimitResult",
    "RateLimiter",
    "RateLimiterConfigError",
    "RateLimiterError",
    "RateLimiterHttpError",
    "RateLimiterUnavailableError",
    "RateLimiterValidationError",
]

SDK_VERSION = "1.0.0"

_API_KEY_PATTERN = re.compile(r"^rlk_[A-Za-z0-9_-]{43}[0-9a-f]{8}$")
_ACTION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_IDENTIFIER_MAX_LENGTH = 256
_LIMIT_MAX = 1_000_000
_WINDOW_MAX_SECONDS = 2_592_000
_IP_MAX_LENGTH = 64
_MAX_RETRIES_CAP = 2
_NON_RETRYABLE_4XX = frozenset({400, 401, 403, 404, 405, 413, 415, 422})
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RateLimitResult:
    """Decision for one request. ``reset`` is a Unix timestamp in milliseconds."""

    success: bool
    limit: int
    remaining: int
    reset: int
    is_blocked: bool
    reason: Optional[str] = None


@dataclass(frozen=True)
class FailOpenEvent:
    error: Optional[BaseException]
    attempts: int
    action: str


class RateLimiterError(Exception):
    """Base class for every error raised by this SDK."""


class RateLimiterConfigError(RateLimiterError):
    """Invalid constructor configuration."""


class RateLimiterValidationError(RateLimiterError):
    """Invalid arguments to check(); raised before any network I/O."""


class RateLimiterHttpError(RateLimiterError):
    """Non-retryable HTTP error from the edge API (400, 401, 403, 413, 415)."""

    def __init__(self, status: int, code: str, message: str, request_id: Optional[str]) -> None:
        super().__init__(f"{message} (HTTP {status}, {code})")
        self.status = status
        self.code = code
        self.request_id = request_id


class RateLimiterUnavailableError(RateLimiterError):
    """Every attempt failed and fail_open is disabled."""

    def __init__(self, attempts: int, cause: Optional[BaseException]) -> None:
        super().__init__(f"Rate limit service unavailable after {attempts} attempt(s)")
        self.attempts = attempts
        self.__cause__ = cause


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

_Payload = Dict[str, Union[str, int]]


@dataclass(frozen=True)
class _Decision:
    result: RateLimitResult
    reset_after_ms: Optional[int]


@dataclass(frozen=True)
class _Retryable:
    error: BaseException


@dataclass(frozen=True)
class _Fatal:
    error: RateLimiterError


_Attempt = Union[_Decision, _Retryable, _Fatal]


def _non_negative_int(value: Any) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _parse_result(body: Any) -> Optional[RateLimitResult]:
    """Runtime validation of the wire format; the SDK never trusts it blindly."""
    if not isinstance(body, dict):
        return None
    success = body.get("success")
    is_blocked = body.get("isBlocked")
    limit = _non_negative_int(body.get("limit"))
    remaining = _non_negative_int(body.get("remaining"))
    reset = _non_negative_int(body.get("reset"))
    reason = body.get("reason")
    if not isinstance(success, bool) or not isinstance(is_blocked, bool):
        return None
    if limit is None or remaining is None or reset is None:
        return None
    if reason is not None and not isinstance(reason, str):
        return None
    return RateLimitResult(
        success=success,
        limit=limit,
        remaining=remaining,
        reset=reset,
        is_blocked=is_blocked,
        reason=reason,
    )


def _check_int(name: str, value: Any, minimum: int, maximum: int, error: Type[RateLimiterError]) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > maximum:
        raise error(f"{name} must be an integer between {minimum} and {maximum}")
    return value


class _LocalBlockCache:
    """Thread-safe bounded LRU on a monotonic clock (immune to wall-clock jumps)."""

    def __init__(self, max_entries: int) -> None:
        self._max_entries = max_entries
        self._entries: "OrderedDict[str, Tuple[RateLimitResult, float]]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[RateLimitResult]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            result, expires_at = entry
            if expires_at <= time.monotonic():
                del self._entries[key]
                return None
            return result

    def set(self, key: str, result: RateLimitResult, ttl_ms: float) -> None:
        if not ttl_ms > 0:
            return
        with self._lock:
            self._entries.pop(key, None)
            self._entries[key] = (result, time.monotonic() + ttl_ms / 1000.0)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Client for the edge rate-limit API. Create one per process and reuse it."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: Optional[str] = None,
        timeout_ms: int = 1_000,
        max_retries: int = _MAX_RETRIES_CAP,
        backoff_base_ms: int = 100,
        backoff_max_ms: int = 1_000,
        fail_open: bool = True,
        local_block_cache: bool = True,
        local_block_cache_max_entries: int = 10_000,
        default_action: str = "default",
        on_fail_open: Optional[Callable[[FailOpenEvent], None]] = None,
        async_client: Optional[httpx.AsyncClient] = None,
        sync_client: Optional[httpx.Client] = None,
    ) -> None:
        if not isinstance(api_key, str) or not _API_KEY_PATTERN.match(api_key):
            # Deliberately does not echo the key.
            raise RateLimiterConfigError("api_key is missing or malformed (expected rlk_...)")
        self._api_key = api_key

        raw_base_url = base_url if base_url is not None else os.environ.get("RATELIMIT_API_URL", "").strip()
        if not raw_base_url:
            raise RateLimiterConfigError("base_url is required (argument or RATELIMIT_API_URL environment variable)")
        parts = urlsplit(raw_base_url)
        if not parts.scheme or not parts.netloc:
            raise RateLimiterConfigError("base_url must be an absolute URL")
        hostname = (parts.hostname or "").lower()
        if parts.scheme != "https" and not (parts.scheme == "http" and hostname in _LOCAL_HOSTS):
            raise RateLimiterConfigError("base_url must use https (http is allowed for localhost only)")
        self._endpoint = raw_base_url.rstrip("/") + "/v1/check"

        self._timeout_ms = _check_int("timeout_ms", timeout_ms, 1, 60_000, RateLimiterConfigError)
        self._max_retries = _check_int("max_retries", max_retries, 0, _MAX_RETRIES_CAP, RateLimiterConfigError)
        self._backoff_base_ms = _check_int("backoff_base_ms", backoff_base_ms, 0, 60_000, RateLimiterConfigError)
        self._backoff_max_ms = _check_int("backoff_max_ms", backoff_max_ms, 0, 60_000, RateLimiterConfigError)
        cache_max = _check_int(
            "local_block_cache_max_entries", local_block_cache_max_entries, 1, 1_000_000, RateLimiterConfigError
        )
        if not isinstance(default_action, str) or not _ACTION_PATTERN.match(default_action):
            raise RateLimiterConfigError("default_action must match ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")

        self._fail_open = bool(fail_open)
        self._default_action = default_action
        self._on_fail_open = on_fail_open
        self._block_cache: Optional[_LocalBlockCache] = _LocalBlockCache(cache_max) if local_block_cache else None

        self._headers = {
            "authorization": f"Bearer {self._api_key}",
            "content-type": "application/json",
            "accept": "application/json",
            "x-sdk-version": f"python/{SDK_VERSION}",
        }
        self._async_client = async_client
        self._async_client_loop: Optional[asyncio.AbstractEventLoop] = None
        self._owns_async_client = async_client is None
        self._sync_client = sync_client
        self._owns_sync_client = sync_client is None
        self._client_lock = threading.Lock()

    def __repr__(self) -> str:  # never leak the key through logs / tracebacks
        return f"RateLimiter(endpoint={self._endpoint!r})"

    # -- public API ---------------------------------------------------------

    async def check(
        self,
        identifier: str,
        limit: int,
        window_in_seconds: int,
        *,
        action: Optional[str] = None,
        ip: Optional[str] = None,
        ip_limit: Optional[int] = None,
    ) -> RateLimitResult:
        """Async check (non-blocking). Returns for both allowed and blocked outcomes."""
        payload, cache_key = self._prepare(identifier, limit, window_in_seconds, action, ip, ip_limit)
        cached = self._block_cache.get(cache_key) if self._block_cache is not None else None
        if cached is not None:
            return cached

        client = self._get_async_client()
        body = json.dumps(payload, separators=(",", ":"))
        last_error: Optional[BaseException] = None
        total_attempts = self._max_retries + 1

        for attempt in range(total_attempts):
            if attempt > 0:
                await asyncio.sleep(self._backoff_delay(attempt - 1))
            try:
                response = await client.post(
                    self._endpoint, content=body, headers=self._headers, timeout=self._timeout_ms / 1000.0
                )
                outcome = self._interpret(response.status_code, response.headers, response.content)
            except httpx.HTTPError as exc:  # timeouts, connection errors, protocol errors
                outcome = _Retryable(exc)

            if isinstance(outcome, _Decision):
                self._remember_block(cache_key, outcome, window_in_seconds)
                return outcome.result
            if isinstance(outcome, _Fatal):
                raise outcome.error
            last_error = outcome.error

        return self._exhausted(payload, limit, window_in_seconds, total_attempts, last_error)

    def check_sync(
        self,
        identifier: str,
        limit: int,
        window_in_seconds: int,
        *,
        action: Optional[str] = None,
        ip: Optional[str] = None,
        ip_limit: Optional[int] = None,
    ) -> RateLimitResult:
        """Blocking check for WSGI / threaded code. Same semantics as check()."""
        payload, cache_key = self._prepare(identifier, limit, window_in_seconds, action, ip, ip_limit)
        cached = self._block_cache.get(cache_key) if self._block_cache is not None else None
        if cached is not None:
            return cached

        client = self._get_sync_client()
        body = json.dumps(payload, separators=(",", ":"))
        last_error: Optional[BaseException] = None
        total_attempts = self._max_retries + 1

        for attempt in range(total_attempts):
            if attempt > 0:
                time.sleep(self._backoff_delay(attempt - 1))
            try:
                response = client.post(
                    self._endpoint, content=body, headers=self._headers, timeout=self._timeout_ms / 1000.0
                )
                outcome = self._interpret(response.status_code, response.headers, response.content)
            except httpx.HTTPError as exc:
                outcome = _Retryable(exc)

            if isinstance(outcome, _Decision):
                self._remember_block(cache_key, outcome, window_in_seconds)
                return outcome.result
            if isinstance(outcome, _Fatal):
                raise outcome.error
            last_error = outcome.error

        return self._exhausted(payload, limit, window_in_seconds, total_attempts, last_error)

    def clear_local_cache(self) -> None:
        """Drop all locally cached blocks."""
        if self._block_cache is not None:
            self._block_cache.clear()

    async def aclose(self) -> None:
        if self._async_client is not None and self._owns_async_client:
            await self._async_client.aclose()
            self._async_client = None
            self._async_client_loop = None

    def close(self) -> None:
        if self._sync_client is not None and self._owns_sync_client:
            self._sync_client.close()
            self._sync_client = None

    async def __aenter__(self) -> "RateLimiter":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    def __enter__(self) -> "RateLimiter":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- shared logic (identical for async and sync paths) --------------------

    def _prepare(
        self,
        identifier: str,
        limit: int,
        window_in_seconds: int,
        action: Optional[str],
        ip: Optional[str],
        ip_limit: Optional[int],
    ) -> Tuple[_Payload, str]:
        if not isinstance(identifier, str) or not 1 <= len(identifier) <= _IDENTIFIER_MAX_LENGTH:
            raise RateLimiterValidationError(
                f"identifier must be a string of 1-{_IDENTIFIER_MAX_LENGTH} characters"
            )
        _check_int("limit", limit, 1, _LIMIT_MAX, RateLimiterValidationError)
        _check_int("window_in_seconds", window_in_seconds, 1, _WINDOW_MAX_SECONDS, RateLimiterValidationError)

        resolved_action = self._default_action if action is None else action
        if not isinstance(resolved_action, str) or not _ACTION_PATTERN.match(resolved_action):
            raise RateLimiterValidationError("action must match ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")

        payload: _Payload = {
            "identifier": identifier,
            "action": resolved_action,
            "limit": limit,
            "windowSeconds": window_in_seconds,
        }
        if ip is not None:
            if not isinstance(ip, str) or not ip.strip() or len(ip) > _IP_MAX_LENGTH:
                raise RateLimiterValidationError("ip must be a non-empty string of at most 64 characters")
            payload["ip"] = ip.strip()
        if ip_limit is not None:
            if "ip" not in payload:
                raise RateLimiterValidationError("ip_limit requires ip")
            payload["ipLimit"] = _check_int("ip_limit", ip_limit, 1, _LIMIT_MAX, RateLimiterValidationError)

        cache_key = json.dumps(
            [
                payload["action"],
                payload["identifier"],
                payload.get("ip"),
                payload["limit"],
                payload["windowSeconds"],
                payload.get("ipLimit"),
            ]
        )
        return payload, cache_key

    def _interpret(self, status: int, headers: Mapping[str, str], content: bytes) -> _Attempt:
        if status in (200, 429):
            try:
                body = json.loads(content)
            except ValueError as exc:
                return _Retryable(exc)
            result = _parse_result(body)
            if result is None:
                # e.g. an upstream proxy's own 429 page: not a decision we can trust.
                return _Retryable(RateLimiterError(f"Unexpected response body (HTTP {status})"))
            raw_after = headers.get("x-ratelimit-reset-after-ms")
            reset_after = int(raw_after) if raw_after is not None and raw_after.isdigit() else None
            return _Decision(result, reset_after)

        if status in _NON_RETRYABLE_4XX:
            code = "http_error"
            message = "Request rejected by rate limit service"
            request_id = headers.get("x-request-id")
            try:
                body = json.loads(content)
            except ValueError:
                body = None
            if isinstance(body, dict):
                if isinstance(body.get("error"), str):
                    code = body["error"]
                if isinstance(body.get("message"), str):
                    message = body["message"]
                if request_id is None and isinstance(body.get("requestId"), str):
                    request_id = body["requestId"]
            return _Fatal(RateLimiterHttpError(status, code, message, request_id))

        # 5xx, 408 and anything unexpected: retry with backoff.
        return _Retryable(RateLimiterError(f"Rate limit service returned HTTP {status}"))

    def _backoff_delay(self, retry_index: int) -> float:
        """Exponential backoff with equal jitter, in seconds."""
        exp = min(self._backoff_max_ms, self._backoff_base_ms * (1 << retry_index))
        return (exp / 2 + random.random() * (exp / 2)) / 1000.0

    def _remember_block(self, cache_key: str, decision: _Decision, window_in_seconds: int) -> None:
        result = decision.result
        if self._block_cache is None or result.success or result.reason == "fail_open":
            return
        window_cap = window_in_seconds * 2_000
        # Prefer the server-measured duration (drift-proof); fall back to the
        # absolute reset compared with the local wall clock.
        if decision.reset_after_ms is not None:
            ttl: float = decision.reset_after_ms
        else:
            ttl = result.reset - time.time() * 1000
        self._block_cache.set(cache_key, result, min(max(ttl, 0.0), float(window_cap)))

    def _exhausted(
        self,
        payload: _Payload,
        limit: int,
        window_in_seconds: int,
        attempts: int,
        last_error: Optional[BaseException],
    ) -> RateLimitResult:
        if not self._fail_open:
            raise RateLimiterUnavailableError(attempts, last_error)
        if self._on_fail_open is not None:
            try:
                self._on_fail_open(FailOpenEvent(error=last_error, attempts=attempts, action=str(payload["action"])))
            except Exception:  # noqa: BLE001 - an observability hook must never break requests
                pass
        return RateLimitResult(
            success=True,
            limit=limit,
            remaining=limit,
            reset=int(time.time() * 1000) + window_in_seconds * 1000,
            is_blocked=False,
            reason="fail_open",
        )

    def _get_async_client(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if not self._owns_async_client and self._async_client is not None:
            return self._async_client
        # An AsyncClient's connection pool is bound to the loop that created it.
        # Rebuild it if we are now running on a different loop (e.g. code that
        # calls asyncio.run() per request) instead of failing on a dead loop.
        if self._async_client is None or self._async_client_loop is not loop:
            self._async_client = httpx.AsyncClient(
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
                follow_redirects=False,
            )
            self._async_client_loop = loop
        return self._async_client

    def _get_sync_client(self) -> httpx.Client:
        if self._sync_client is None:
            with self._client_lock:
                if self._sync_client is None:
                    self._sync_client = httpx.Client(
                        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
                        follow_redirects=False,
                    )
        return self._sync_client
