#!/usr/bin/env python3
"""
cora_sentinel.report - anonymized violation reports for cora-security issue logging.

SCHEMA STATUS: cora-security defines no ingress schema yet (README only), so
`cora.security.violation/v1` below is a PROPOSAL. Commit the file written by
    cora-report --write-schema schema/violation.schema.json
into cora-security and change it there; this module validates against it.

What a report contains: what was contacted (blocklist entry, destination IP only
if it is a public address, port), what Cora did, an hour-truncated time, and a
salted pseudonym for the task so repeats can be recognised.

What it never contains: hostname, user, pid, virtual IP, cgroup/task name,
command line, local ports or addresses, the model's free-text reason, exact
timestamps. The salt lives OUTSIDE the report directory on purpose: zip the
directory for an issue and the pseudonyms stay unlinkable.

Reports are written locally and never sent. Review, then:
    gh issue create --repo nkaralus/cora-security --title "<title>" --body-file <id>.md
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

SCHEMA_ID = "cora.security.violation/v1"
TYPES = ["tracker_domain", "rogue_subnet"]
VERDICTS = ["ALLOW", "THROTTLE", "ISOLATE", "SUSPEND", "TERMINATE", "ESCALATE"]
IP_CLASSES = ["public", "private", "link_local", "other"]
DEFAULT_SALT = "~/.config/cora/report_salt"

JSON_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://github.com/nkaralus/cora-security/violation.schema.json",
    "title": SCHEMA_ID,
    "type": "object",
    "additionalProperties": False,
    "required": ["schema", "report_id", "observed_hour", "violation", "response", "task_ref", "process"],
    "properties": {
        "schema": {"const": SCHEMA_ID},
        "report_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
        "observed_hour": {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:00:00Z$"},
        "task_ref": {"type": "string", "pattern": "^[0-9a-f]{12}$"},
        "process": {"type": ["string", "null"], "maxLength": 64},
        "violation": {
            "type": "object", "additionalProperties": False,
            "required": ["type", "list", "entry", "destination"],
            "properties": {
                "type": {"enum": TYPES},
                "list": {"type": "string", "maxLength": 64},
                "entry": {"type": "string", "maxLength": 260},
                "destination": {
                    "type": "object", "additionalProperties": False,
                    "required": ["ip", "port", "ip_class"],
                    "properties": {
                        "ip": {"type": ["string", "null"]},
                        "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                        "ip_class": {"enum": IP_CLASSES}}}}},
        "response": {
            "type": "object", "additionalProperties": False,
            "required": ["verdict", "enforced", "policy", "model_confidence"],
            "properties": {
                "verdict": {"enum": VERDICTS},
                "enforced": {"type": "boolean"},
                "policy": {"type": ["string", "null"], "maxLength": 64},
                "model_confidence": {"type": "number", "minimum": 0, "maximum": 1}}}},
}


def validate_report(d: dict) -> None:
    """Strict check mirroring JSON_SCHEMA. Raises ValueError."""
    def keys(o, want, where):
        if not isinstance(o, dict) or set(o) != set(want):
            raise ValueError(f"{where}: keys must be exactly {sorted(want)}")
    keys(d, JSON_SCHEMA["required"], "report")
    if d["schema"] != SCHEMA_ID:
        raise ValueError("schema id")
    if not (isinstance(d["report_id"], str) and len(d["report_id"]) == 32):
        raise ValueError("report_id")
    if not (isinstance(d["task_ref"], str) and len(d["task_ref"]) == 12):
        raise ValueError("task_ref")
    datetime.strptime(d["observed_hour"], "%Y-%m-%dT%H:00:00Z")
    if d["process"] is not None and not isinstance(d["process"], str):
        raise ValueError("process")
    v = d["violation"]
    keys(v, ["type", "list", "entry", "destination"], "violation")
    if v["type"] not in TYPES or not isinstance(v["list"], str) or not isinstance(v["entry"], str):
        raise ValueError("violation fields")
    dst = v["destination"]
    keys(dst, ["ip", "port", "ip_class"], "destination")
    if dst["ip"] is not None:
        ipaddress.ip_address(dst["ip"])
    if not (isinstance(dst["port"], int) and 1 <= dst["port"] <= 65535) or dst["ip_class"] not in IP_CLASSES:
        raise ValueError("destination fields")
    r = d["response"]
    keys(r, ["verdict", "enforced", "policy", "model_confidence"], "response")
    if r["verdict"] not in VERDICTS or not isinstance(r["enforced"], bool):
        raise ValueError("response fields")
    if not (isinstance(r["model_confidence"], (int, float)) and 0 <= r["model_confidence"] <= 1):
        raise ValueError("model_confidence")


class Reporter:
    def __init__(self, out_dir: str, salt_path: str = DEFAULT_SALT, include_process: bool = False,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.out = Path(out_dir)
        self.salt = self._load_salt(Path(os.path.expanduser(salt_path)))
        self.include_process = include_process
        self.clock = clock
        self._seen: set = set()

    @staticmethod
    def _load_salt(p: Path) -> bytes:
        if p.exists():
            return bytes.fromhex(p.read_text().strip())
        p.parent.mkdir(parents=True, exist_ok=True)
        salt = secrets.token_bytes(32)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(salt.hex())
        return salt

    def task_ref(self, task_id: str) -> str:
        return hmac.new(self.salt, task_id.encode(), hashlib.sha256).hexdigest()[:12]

    def build(self, ev: dict, decision: dict) -> dict:
        evi = ev["anomaly"]["evidence"]
        bl = evi["blocklist"]
        subj = ev["subject"]
        cls = evi.get("dest_class", "other")
        proc = None
        if self.include_process:
            argv0 = (subj.get("cmdline") or "").split(" ", 1)[0]
            proc = os.path.basename(argv0)[:64] or None
        hour = self.clock().astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        rep = {
            "schema": SCHEMA_ID,
            "report_id": uuid.uuid4().hex,
            "observed_hour": hour.strftime("%Y-%m-%dT%H:00:00Z"),
            "task_ref": self.task_ref(subj.get("cgroup") or subj["name"]),
            "process": proc,
            "violation": {
                "type": bl["kind"], "list": bl["list"], "entry": bl["entry"],
                "destination": {
                    # a private/LAN address would map the reporter's network: omit it
                    "ip": evi["remote_ip"] if cls == "public" else None,
                    "port": int(evi["remote_port"]),
                    "ip_class": cls if cls in IP_CLASSES else "other"}},
            "response": {
                "verdict": decision["final"],
                "enforced": str(decision.get("action", "")).startswith("done:"),
                "policy": decision.get("policy"),
                "model_confidence": round(float(decision["model"]["confidence"]), 1)},
        }
        validate_report(rep)
        return rep

    @staticmethod
    def issue_title(rep: dict) -> str:
        v = rep["violation"]
        return f"[violation] {v['type']}: {v['entry']}"

    @staticmethod
    def issue_markdown(rep: dict) -> str:
        v, r = rep["violation"], rep["response"]
        return (f"## {Reporter.issue_title(rep)}\n\n"
                f"Task `{rep['task_ref']}` contacted a `{v['type']}` entry from list `{v['list']}`. "
                f"Response: **{r['verdict']}** ({'enforced' if r['enforced'] else 'not enforced'}).\n\n"
                f"```json\n{json.dumps(rep, indent=2)}\n```\n")

    def report(self, ev: dict, decision: dict) -> Optional[Path]:
        rep = self.build(ev, decision)
        key = (rep["task_ref"], rep["violation"]["list"], rep["violation"]["entry"], rep["observed_hour"])
        if key in self._seen:          # same task, same entry, same hour: one report
            return None
        self._seen.add(key)
        self.out.mkdir(parents=True, exist_ok=True)
        base = self.out / rep["report_id"]
        base.with_suffix(".json").write_text(json.dumps(rep, indent=2) + "\n")
        base.with_suffix(".md").write_text(self.issue_markdown(rep))
        print(f"[report] {base}.md  ->  gh issue create --repo nkaralus/cora-security "
              f"--title \"{self.issue_title(rep)}\" --body-file {base}.md", file=sys.stderr)
        return base.with_suffix(".json")


def main() -> int:
    ap = argparse.ArgumentParser(prog="cora-report", description="anonymized violation report tooling")
    ap.add_argument("--write-schema", metavar="PATH", help="write the JSON Schema (cora.security.violation/v1)")
    a = ap.parse_args()
    if a.write_schema:
        Path(a.write_schema).write_text(json.dumps(JSON_SCHEMA, indent=2) + "\n")
        print(f"wrote {a.write_schema}")
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
