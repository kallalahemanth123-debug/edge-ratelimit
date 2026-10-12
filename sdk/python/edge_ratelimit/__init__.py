"""Edge Rate Limit & Abuse Protection — Python SDK."""

from .rate_limiter import (
    SDK_VERSION,
    FailOpenEvent,
    RateLimiter,
    RateLimiterConfigError,
    RateLimiterError,
    RateLimiterHttpError,
    RateLimiterUnavailableError,
    RateLimiterValidationError,
    RateLimitResult,
)

__version__ = SDK_VERSION

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
    "__version__",
]
