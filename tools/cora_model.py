#!/usr/bin/env python3
"""
cora_model - the caller's side of tools/cora_model_worker.py. Never imports llama_cpp: inference runs in a child
process, so a crash inside llama.cpp (SIGSEGV on a bad grammar) costs a MODEL_CRASH, never the harness or cora-exec.

    w = ModelWorker("models/qwen2.5-3b-instruct-q4_k_m.gguf")
    reply = w.complete(gbnf, messages, max_tokens=48)      # {"text", "prompt_tokens", "completion_tokens", "ms"}
    w.close()

Raises ModelError with code MODEL_CRASH (the worker died: its exit status and stderr tail are in the detail),
MODEL_TIMEOUT (no reply in time: the worker is killed), MODEL_ERROR (the worker answered with an error) or
MODEL_UNAVAILABLE (no model file, or it never became ready). A worker that crashed is restarted on the next call.
"""
from __future__ import annotations

import json
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

WORKER = Path(__file__).resolve().parent / "cora_model_worker.py"
DEFAULT_MODEL = Path(__file__).resolve().parent.parent / "models" / "qwen2.5-3b-instruct-q4_k_m.gguf"


class ModelError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


def describe_exit(rc: Optional[int]) -> str:
    if rc is None:
        return "still running"
    if rc < 0:
        try:
            return f"killed by {signal.Signals(-rc).name} (rc {rc})"
        except ValueError:
            return f"killed by signal {-rc}"
    return f"exited with status {rc}"


class ModelWorker:
    def __init__(self, model_path: "str | os.PathLike" = DEFAULT_MODEL, *, timeout_s: float = 120.0,
                 start_timeout_s: float = 120.0, argv: Optional[List[str]] = None):
        self.model_path = str(model_path)
        self.timeout_s, self.start_timeout_s = timeout_s, start_timeout_s
        self.argv = argv or [sys.executable, str(WORKER), self.model_path]
        self.proc: Optional[subprocess.Popen] = None
        self.calls = 0                                   # requests sent (crashed ones included)
        self._buf = b""
        self._next = 0
        self._err = None

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if argv_needs_model(self.argv) and not Path(self.model_path).is_file():
            raise ModelError("MODEL_UNAVAILABLE", f"no model file at {self.model_path}")
        self._err = tempfile.TemporaryFile()
        self._buf = b""
        self.proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._err,
                                     start_new_session=True)
        try:
            msg = self._read(time.monotonic() + self.start_timeout_s)
        except ModelError as e:
            raise ModelError("MODEL_UNAVAILABLE", f"the worker never became ready: {e.detail}") from None
        if msg.get("ready") is not True:
            self.close()
            raise ModelError("MODEL_UNAVAILABLE", f"unexpected first line from the worker: {msg!r}"[:300])

    def close(self) -> None:
        if self.proc is not None:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._kill()
            self.proc = None

    def _kill(self) -> None:
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.proc.wait()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ------------------------------------------------------------------ requests
    def complete(self, grammar: str, messages: List[Dict[str, str]], max_tokens: int = 48) -> Dict[str, Any]:
        if self.proc is None or self.proc.poll() is not None:
            self.start()
        self._next += 1
        req = {"id": self._next, "grammar": grammar, "messages": messages, "max_tokens": max_tokens}
        self.calls += 1
        t0 = time.monotonic()
        try:
            self.proc.stdin.write((json.dumps(req) + "\n").encode())
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            raise self._crashed()
        reply = self._read(t0 + self.timeout_s)
        if reply.get("id") != req["id"]:
            self.close()
            raise ModelError("MODEL_ERROR", f"reply for request {reply.get('id')!r}, expected {req['id']}")
        if "error" in reply:
            raise ModelError("MODEL_ERROR", str(reply["error"])[:300])
        reply["ms"] = round((time.monotonic() - t0) * 1000)
        return reply

    def _read(self, deadline: float) -> dict:
        sel = selectors.DefaultSelector()
        sel.register(self.proc.stdout, selectors.EVENT_READ)
        try:
            while b"\n" not in self._buf:
                left = deadline - time.monotonic()
                if left <= 0:
                    self._kill()
                    self.proc = None
                    raise ModelError("MODEL_TIMEOUT", "no reply in time; the worker was killed")
                if not sel.select(timeout=left):
                    continue
                chunk = os.read(self.proc.stdout.fileno(), 65536)
                if not chunk:
                    raise self._crashed()
                self._buf += chunk
        finally:
            sel.close()
        line, self._buf = self._buf.split(b"\n", 1)
        try:
            return json.loads(line)
        except ValueError:
            self.close()
            raise ModelError("MODEL_ERROR", f"unreadable reply: {line[:120]!r}")

    def _crashed(self) -> ModelError:
        rc = self.proc.wait()
        tail = b""
        if self._err is not None:
            self._err.seek(0)
            tail = self._err.read()[-600:]
        self.proc = None
        lines = [l for l in tail.decode("utf-8", "replace").splitlines() if l.strip()][-3:]
        return ModelError("MODEL_CRASH", f"the model worker {describe_exit(rc)}" + (f": {' | '.join(lines)}" if lines else ""))


def argv_needs_model(argv: List[str]) -> bool:
    return len(argv) >= 2 and Path(argv[1]).resolve() == WORKER
