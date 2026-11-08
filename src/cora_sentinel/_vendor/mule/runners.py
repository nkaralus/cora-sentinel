"""Thin, stdlib-only request builders for local runtimes.

backend      endpoint                      constraint field
-----------  ----------------------------  --------------------------------
ollama       /api/chat                     format = JSON schema
openai       /v1/chat/completions          response_format = json_schema
             (vLLM, LM Studio, llama-server)
llamacpp     /v1/chat/completions          grammar = GBNF   (llama-server)

Parameter names move between runtime releases. Confirm against your version's docs;
the validator is the safety net either way.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict, List, Optional

from .prompt import RECOMMENDED_SAMPLING

__all__ = ["build_payload", "endpoint", "extract_text", "generate", "DEFAULT_URLS"]

DEFAULT_URLS = {
    "ollama": "http://localhost:11434",
    "openai": "http://localhost:8000",     # vLLM; LM Studio is :1234
    "llamacpp": "http://localhost:8080",   # llama-server
}


def endpoint(backend: str, base_url: Optional[str] = None) -> str:
    base = (base_url or DEFAULT_URLS[backend]).rstrip("/")
    return base + ("/api/chat" if backend == "ollama" else "/v1/chat/completions")


def build_payload(
    backend: str, model: str, messages: List[Dict[str, str]], *,
    schema: Optional[Dict[str, Any]] = None, grammar: Optional[str] = None,
    sampling: Optional[Dict[str, Any]] = None, think: bool = False,
) -> Dict[str, Any]:
    s = dict(RECOMMENDED_SAMPLING, **(sampling or {}))
    if backend == "ollama":
        p: Dict[str, Any] = {
            "model": model, "messages": messages, "stream": False, "think": think,
            "options": {"temperature": s["temperature"], "num_predict": s["max_tokens"], "stop": s["stop"]},
        }
        if schema:
            p["format"] = schema
        return p
    if backend in ("openai", "llamacpp"):
        p = {
            "model": model, "messages": messages, "stream": False,
            "temperature": s["temperature"], "max_tokens": s["max_tokens"], "stop": s["stop"],
            "chat_template_kwargs": {"enable_thinking": think},  # Qwen3 family
        }
        if backend == "openai" and schema:
            p["response_format"] = {"type": "json_schema",
                                    "json_schema": {"name": "mule_task_block", "strict": True, "schema": schema}}
        if backend == "llamacpp" and grammar:
            p["grammar"] = grammar
        return p
    raise ValueError(f"unknown backend {backend!r}")


def extract_text(backend: str, response: Dict[str, Any]) -> str:
    if backend == "ollama":
        return response["message"]["content"]
    return response["choices"][0]["message"]["content"]


def generate(
    backend: str, model: str, messages: List[Dict[str, str]], *,
    base_url: Optional[str] = None, schema=None, grammar=None, timeout: float = 120.0, **kw,
) -> str:
    payload = build_payload(backend, model, messages, schema=schema, grammar=grammar, **kw)
    req = urllib.request.Request(
        endpoint(backend, base_url), data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return extract_text(backend, json.load(r))
