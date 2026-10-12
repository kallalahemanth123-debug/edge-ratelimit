#!/usr/bin/env python3
"""
Local Upstash REST emulator backed by a real Redis server (development only).

Speaks the subset of the Upstash REST protocol the worker uses:
  POST /            body: ["CMD", "arg", ...]       -> {"result": ...} | 400 {"error": "..."}
  POST /pipeline    body: [["CMD", ...], ...]       -> [{"result": ...} | {"error": "..."}, ...]

Fault injection for testing fail-open behaviour:
  POST /__control   body: {"delayMs": 500, "failStatus": 503}   (0 / null to clear)

Usage:
  pip install redis
  python dev/upstash_emulator.py --port 8079 --token dev-token --redis redis://127.0.0.1:6379/0

Prefer the official community image for anything beyond local tests:
  docker run -p 8079:80 -e SRH_MODE=env -e SRH_TOKEN=dev-token \
    -e SRH_CONNECTION_STRING=redis://host.docker.internal:6379 hiett/serverless-redis-http
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, List, Optional, Union

import redis

JsonValue = Union[None, int, str, List["JsonValue"]]


class Faults:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.delay_ms = 0
        self.fail_status: Optional[int] = None

    def snapshot(self) -> "tuple[int, Optional[int]]":
        with self._lock:
            return self.delay_ms, self.fail_status

    def update(self, delay_ms: int, fail_status: Optional[int]) -> None:
        with self._lock:
            self.delay_ms = delay_ms
            self.fail_status = fail_status


def to_json(value: Any) -> JsonValue:
    if value is None:
        return None
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple, set)):
        return [to_json(v) for v in value]
    if isinstance(value, dict):
        flat: List[JsonValue] = []
        for k, v in value.items():
            flat.extend([to_json(k), to_json(v)])
        return flat
    return str(value)


def error_text(exc: "redis.ResponseError") -> str:
    """redis-py strips the RESP error code; restore it so replies match real Redis/Upstash."""
    message = str(exc)
    if isinstance(exc, redis.exceptions.NoScriptError):
        return f"NOSCRIPT {message}"
    if message.split(" ", 1)[0].isupper():
        return message
    return f"ERR {message}"


def make_handler(pool: "redis.ConnectionPool", token: str, faults: Faults) -> type:
    def run(args: List[str]) -> "dict[str, JsonValue]":
        if not args or not all(isinstance(a, str) for a in args):
            return {"error": "ERR command must be a non-empty array of strings"}
        conn = pool.get_connection()
        try:
            conn.send_command(*args)
            reply = conn.read_response()
            return {"result": to_json(reply)}
        except redis.ResponseError as exc:
            return {"error": error_text(exc)}
        finally:
            pool.release(conn)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _send(self, status: int, payload: Any) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("content-length") or 0)
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw or b"null")
            except json.JSONDecodeError:
                self._send(400, {"error": "ERR invalid JSON"})
                return

            if self.path == "/__control":
                delay = int(payload.get("delayMs") or 0)
                status = payload.get("failStatus")
                faults.update(delay, int(status) if status else None)
                self._send(200, {"result": "OK"})
                return

            if self.headers.get("authorization") != f"Bearer {token}":
                self._send(401, {"error": "Unauthorized"})
                return

            delay_ms, fail_status = faults.snapshot()
            if delay_ms > 0:
                time.sleep(delay_ms / 1000)
            if fail_status is not None:
                self._send(fail_status, {"error": "injected failure"})
                return

            if self.path in ("/", ""):
                result = run(payload)
                self._send(400 if "error" in result else 200, result)
            elif self.path == "/pipeline":
                if not isinstance(payload, list):
                    self._send(400, {"error": "ERR pipeline body must be an array"})
                    return
                self._send(200, [run(cmd) for cmd in payload])
            else:
                self._send(404, {"error": "not found"})

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8079)
    parser.add_argument("--token", required=True)
    parser.add_argument("--redis", default="redis://127.0.0.1:6379/0")
    args = parser.parse_args()

    # Upstash speaks RESP2 shapes (e.g. HGETALL -> flat array), so force protocol 2.
    pool = redis.ConnectionPool.from_url(args.redis, max_connections=256, protocol=2)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(pool, args.token, Faults()))
    server.daemon_threads = True
    print(f"upstash-emulator listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
