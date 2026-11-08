#!/usr/bin/env python3
"""
cora_model_worker - the ONLY cora-exec process that imports llama_cpp. tools/cora_model.py starts it and talks to it
over its stdin/stdout, one JSON object per line; if llama.cpp brings it down (a malformed grammar makes
llama_sampler_init_grammar return NULL, which llama-cpp-python 0.3.36 adds to the sampler chain unchecked: SIGSEGV),
only this process dies, and the caller reports MODEL_CRASH.

    python tools/cora_model_worker.py MODEL.gguf          (normally started by tools/cora_model.py)

  -> {"ready": true}                                       once the model is loaded
  <- {"id": N, "grammar": GBNF, "messages": [...], "max_tokens": M}
  -> {"id": N, "text": ..., "prompt_tokens": P, "completion_tokens": C}   or   {"id": N, "error": ...}

Deterministic: temperature 0, seed 1. Anything the C library prints goes to stderr: the reply channel is a private
copy of stdout, so a stray printf cannot corrupt a reply.
"""
import json
import os
import sys


def main() -> int:
    chan = os.fdopen(os.dup(1), "w", buffering=1)
    os.dup2(2, 1)                                        # fd 1 is now stderr: library chatter cannot reach the channel
    from llama_cpp import Llama, LlamaGrammar
    llm = Llama(sys.argv[1], n_ctx=int(os.environ.get("CORA_MODEL_CTX", "2048")), verbose=False)
    chan.write(json.dumps({"ready": True}) + "\n")
    for line in sys.stdin:
        req = json.loads(line)
        try:
            r = llm.create_chat_completion(req["messages"], grammar=LlamaGrammar.from_string(req["grammar"], verbose=False),
                                           temperature=0, seed=1, max_tokens=int(req.get("max_tokens", 64)))
            reply = {"id": req["id"], "text": r["choices"][0]["message"]["content"],
                     "prompt_tokens": r["usage"]["prompt_tokens"], "completion_tokens": r["usage"]["completion_tokens"]}
        except Exception as e:
            reply = {"id": req.get("id"), "error": f"{e.__class__.__name__}: {e}"[:300]}
        chan.write(json.dumps(reply) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
