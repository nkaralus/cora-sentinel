#!/usr/bin/env python3
"""Rehearse the dynamic policy against recorded decisions and events. Same as `cora-floor dyn-replay`; see
cora_sentinel/dynreplay.py or docs/dyn-policy.md.

  python tools/dyn_replay.py /var/log/cora-sentinel/decisions.jsonl --events /var/log/cora-sentinel/events.jsonl
"""
import sys

from cora_sentinel.dynreplay import main

if __name__ == "__main__":
    sys.exit(main())
