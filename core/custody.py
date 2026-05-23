"""Tamper-evident chain-of-custody ledger.

The ledger is an append-only JSONL file where every entry includes the
SHA-256 hash of the previous entry. Altering or deleting any past entry
invalidates the hash chain for every entry that follows it — the same
principle that makes blockchains tamper-evident.

This does NOT prevent tampering; it makes tampering detectable. For a real
forensic deployment the ledger should be written to write-once media or
co-signed by an external timestamping authority.
"""
from __future__ import annotations

import datetime as dt
import getpass
import hashlib
import json
import socket
import uuid
from pathlib import Path
from typing import Any

GENESIS_PREV = "0" * 64


def _now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat()


def _entry_hash(entry: dict[str, Any]) -> str:
    """Canonical SHA-256 of an entry, used as the link for the next entry."""
    blob = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class CustodyLedger:
    """Append-only, hash-chained JSONL ledger.

    Each line is a JSON object with this shape:
        {
          "id": "<uuid4>",
          "timestamp_utc": "...",
          "actor": "user@host",
          "action": "REGISTER" | "ACCESS" | "VERIFY" | "TRANSFER" | "NOTE",
          "evidence_id": "<uuid or filename>",
          "details": { ... },
          "prev_hash": "<sha256 of previous entry, or 64 zeros for genesis>",
          "entry_hash": "<sha256 of this entry minus the entry_hash field>"
        }
    """

    def __init__(self, ledger_path: str | Path):
        self.path = Path(ledger_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ read
    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                out.append(json.loads(line))
        return out

    def _last_hash(self) -> str:
        entries = self.entries()
        return entries[-1]["entry_hash"] if entries else GENESIS_PREV

    # ----------------------------------------------------------------- write
    def append(
        self,
        action: str,
        evidence_id: str,
        details: dict[str, Any] | None = None,
        actor: str | None = None,
    ) -> dict[str, Any]:
        if actor is None:
            try:
                actor = f"{getpass.getuser()}@{socket.gethostname()}"
            except Exception:
                actor = "unknown"

        body = {
            "id": str(uuid.uuid4()),
            "timestamp_utc": _now(),
            "actor": actor,
            "action": action,
            "evidence_id": evidence_id,
            "details": details or {},
            "prev_hash": self._last_hash(),
        }
        body["entry_hash"] = _entry_hash(body)

        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(body, sort_keys=True) + "\n")
        return body

    # -------------------------------------------------------------- verify
    def verify(self) -> dict[str, Any]:
        """Walk the chain and confirm every link is intact.

        Returns a report dict with 'ok' (bool), 'entries_checked' (int),
        and 'broken_at' (index or None).
        """
        prev = GENESIS_PREV
        entries = self.entries()
        for i, entry in enumerate(entries):
            stored_hash = entry.get("entry_hash")
            body = {k: v for k, v in entry.items() if k != "entry_hash"}
            recomputed = _entry_hash(body)

            if body.get("prev_hash") != prev:
                return {
                    "ok": False,
                    "entries_checked": i + 1,
                    "broken_at": i,
                    "reason": "prev_hash does not match previous entry's entry_hash",
                }
            if stored_hash != recomputed:
                return {
                    "ok": False,
                    "entries_checked": i + 1,
                    "broken_at": i,
                    "reason": "stored entry_hash does not match recomputed hash",
                }
            prev = stored_hash

        return {"ok": True, "entries_checked": len(entries), "broken_at": None}
