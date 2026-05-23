"""AI Evidence Integrity Tool — CLI.

Commands:
  register <file>           Hash a file, extract metadata, run tamper analysis,
                            and add a REGISTER entry to the custody ledger.
  verify <file>             Re-hash a file and compare it against its most
                            recent REGISTER entry. Adds a VERIFY entry.
  analyze <file>            Run tamper detection and print findings (no
                            ledger write — use for triage).
  ledger                    Print every ledger entry as pretty JSON.
  audit                     Walk the ledger hash chain and report whether it
                            has been tampered with.
  note <evidence_id> <text> Append a free-text NOTE to the custody ledger
                            (chain-of-custody handoffs, observations, etc).

Use --ledger PATH to point at a non-default ledger location. The default is
./custody.jsonl in the working directory.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core import hashing, metadata, tamper
from core.custody import CustodyLedger

DEFAULT_LEDGER = "custody.jsonl"


# ---------------------------------------------------------------- helpers
def _print(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


def _find_register(ledger: CustodyLedger, evidence_id: str) -> dict | None:
    """Latest REGISTER entry for an evidence id, or None."""
    for entry in reversed(ledger.entries()):
        if entry["action"] == "REGISTER" and entry["evidence_id"] == evidence_id:
            return entry
    return None


# --------------------------------------------------------------- commands
def cmd_register(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2

    hashes = hashing.hash_file(path)
    meta = metadata.extract(path)
    findings = tamper.analyze(meta)
    evidence_id = args.evidence_id or path.name

    ledger = CustodyLedger(args.ledger)
    entry = ledger.append(
        action="REGISTER",
        evidence_id=evidence_id,
        details={
            "filename": path.name,
            "hashes": hashes,
            "metadata": meta,
            "tamper_findings": findings,
        },
    )

    print(f"Registered: {evidence_id}")
    print(f"  SHA-256: {hashes['sha256']}")
    print(f"  Ledger entry: {entry['id']}")
    if findings:
        print(f"  Tamper indicators: {len(findings)}")
        for f in findings:
            print(f"    [{f['severity'].upper()}] {f['code']}: {f['message']}")
    else:
        print("  Tamper indicators: none")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2

    ledger = CustodyLedger(args.ledger)
    evidence_id = args.evidence_id or path.name
    registered = _find_register(ledger, evidence_id)
    if registered is None:
        print(f"error: no REGISTER entry found for evidence_id '{evidence_id}'", file=sys.stderr)
        return 3

    expected = registered["details"]["hashes"]
    result = hashing.verify_file(path, expected)
    all_match = all(result.values())

    ledger.append(
        action="VERIFY",
        evidence_id=evidence_id,
        details={
            "registered_entry_id": registered["id"],
            "result": result,
            "integrity_ok": all_match,
        },
    )

    print(f"Verifying: {evidence_id}")
    for alg, matched in result.items():
        status = "OK" if matched else "MISMATCH"
        print(f"  {alg:7s}: {status}")
    if all_match:
        print("Integrity: INTACT — file has not been altered since registration.")
        return 0
    print("Integrity: COMPROMISED — file differs from its registered hashes.")
    return 1


def cmd_analyze(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    meta = metadata.extract(path)
    findings = tamper.analyze(meta)
    _print({"file": str(path), "metadata": meta, "tamper_findings": findings})
    return 0 if not findings else 1


def cmd_ledger(args: argparse.Namespace) -> int:
    ledger = CustodyLedger(args.ledger)
    entries = ledger.entries()
    if not entries:
        print("(ledger is empty)")
        return 0
    _print(entries)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    ledger = CustodyLedger(args.ledger)
    report = ledger.verify()
    _print(report)
    return 0 if report["ok"] else 1


def cmd_note(args: argparse.Namespace) -> int:
    ledger = CustodyLedger(args.ledger)
    entry = ledger.append(
        action="NOTE",
        evidence_id=args.evidence_id,
        details={"note": args.text},
    )
    print(f"Note recorded as entry {entry['id']}")
    return 0


# ------------------------------------------------------------------ main
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="evidence_tool",
        description="Forensic integrity tool: hash verification, metadata analysis, "
                    "tamper detection, and tamper-evident chain of custody.",
    )
    p.add_argument("--ledger", default=DEFAULT_LEDGER,
                   help=f"Path to custody ledger (default: {DEFAULT_LEDGER})")
    sub = p.add_subparsers(dest="command", required=True)

    pr = sub.add_parser("register", help="Hash + fingerprint a new piece of evidence")
    pr.add_argument("file")
    pr.add_argument("--evidence-id", help="Custom evidence id (default: filename)")
    pr.set_defaults(func=cmd_register)

    pv = sub.add_parser("verify", help="Verify a file against its registered hashes")
    pv.add_argument("file")
    pv.add_argument("--evidence-id", help="Custom evidence id (default: filename)")
    pv.set_defaults(func=cmd_verify)

    pa = sub.add_parser("analyze", help="Run tamper detection without writing to ledger")
    pa.add_argument("file")
    pa.set_defaults(func=cmd_analyze)

    pl = sub.add_parser("ledger", help="Dump the custody ledger")
    pl.set_defaults(func=cmd_ledger)

    pad = sub.add_parser("audit", help="Verify the custody ledger's hash chain")
    pad.set_defaults(func=cmd_audit)

    pn = sub.add_parser("note", help="Add a free-text note to the ledger")
    pn.add_argument("evidence_id")
    pn.add_argument("text")
    pn.set_defaults(func=cmd_note)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
