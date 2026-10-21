"""Warm-model daemon so hooks do not pay Laya's multi-second cold start on every call.

`laya-guard serve` loads Laya once and answers newline-delimited JSON requests on a unix socket
(mode 0600, so only your user can talk to it):

    request : {"text": "...", "kind": "prompt"}      or {"ping": true}
    response: the Verdict as JSON (see Verdict.to_dict), or {"pong": true}

Clients (`check`, `hook`) use the daemon when its socket answers a ping and otherwise fall back
to rules-only, never to a cold model load inside a hook. Single-threaded on purpose: the model
is not thread-safe and one request at a time keeps latency predictable.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from .policy import Guard, Verdict

MAX_REQUEST_BYTES = 8 * 1024 * 1024


def default_socket_path() -> str:
    explicit = os.environ.get("LAYA_GUARD_SOCKET")
    if explicit:
        return explicit
    base = os.environ.get("XDG_RUNTIME_DIR") or os.path.join(os.path.expanduser("~"), ".cache", "laya-guard")
    return os.path.join(base, "laya-guard.sock")


def _recv_line(conn: socket.socket) -> bytes:
    chunks, size = [], 0
    while True:
        part = conn.recv(65536)
        if not part:
            break
        chunks.append(part)
        size += len(part)
        if part.endswith(b"\n") or size > MAX_REQUEST_BYTES:
            break
    return b"".join(chunks)


def query(sock_path: str, text: str, kind: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """Ask a running daemon; return the verdict dict, or None if no daemon answers in time."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(sock_path)
            s.sendall(json.dumps({"text": text, "kind": kind}).encode("utf-8") + b"\n")
            raw = _recv_line(s)
        return json.loads(raw) if raw.strip() else None
    except (OSError, ValueError):
        return None


def ping(sock_path: str, timeout: float = 0.5) -> bool:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(sock_path)
            s.sendall(b'{"ping": true}\n')
            return bool(json.loads(_recv_line(s) or b"{}").get("pong"))
    except (OSError, ValueError):
        return False


def serve(guard: Guard, sock_path: Optional[str] = None, warm: bool = True) -> int:
    sock_path = sock_path or default_socket_path()
    path = Path(sock_path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        if ping(sock_path):
            print(f"laya-guard: a daemon is already listening on {sock_path}", file=sys.stderr)
            return 1
        path.unlink()  # stale socket from a crashed daemon
    if warm:
        # Load the model before accepting traffic so the first real request is fast.
        guard.check("warm up", "prompt")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    os.chmod(sock_path, stat.S_IRUSR | stat.S_IWUSR)
    server.listen(16)
    print(f"laya-guard: serving on {sock_path} (Ctrl-C to stop)", file=sys.stderr, flush=True)
    try:
        while True:
            conn, _ = server.accept()
            with conn:
                try:
                    conn.settimeout(10.0)
                    req = json.loads(_recv_line(conn) or b"{}")
                    if req.get("ping"):
                        resp: Dict[str, Any] = {"pong": True}
                    else:
                        resp = guard.check(str(req.get("text", "")), str(req.get("kind", "prompt"))).to_dict()
                except Exception as exc:  # never let one bad request kill the daemon; fail closed for the caller
                    resp = {"error": str(exc)[:200], "decision": "review", "kind": "prompt", "reasons": ["daemon error"]}
                try:
                    conn.sendall(json.dumps(resp).encode("utf-8") + b"\n")
                except OSError:
                    pass
    except KeyboardInterrupt:
        return 0
    finally:
        server.close()
        try:
            path.unlink()
        except OSError:
            pass
