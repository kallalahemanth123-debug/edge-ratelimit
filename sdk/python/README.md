# edge-ratelimit (Python SDK)

```python
from edge_ratelimit import RateLimiter

limiter = RateLimiter("rlk_...", base_url="https://rl.example.com")

# asyncio (FastAPI / Starlette)
result = await limiter.check(user_id, 10, 60, action="llm_generation", ip=client_ip)

# WSGI (Flask / Django)
result = limiter.check_sync(user_id, 5, 60, action="login_attempt", ip=client_ip)

if not result.success:
    ...  # respond 429, Retry-After from result.reset
```

See the repository README for full documentation.
