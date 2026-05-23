"""End-to-end tests for the evidence integrity tool.

Run with:  python -m pytest tests/   (or)   python tests/test_integrity.py
"""
import json
import os
import sys
from pathlib import Path

# Make project root importable when running this file directly.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import hashing, metadata, tamper
from core.custody import CustodyLedger


def test_hash_deterministic(tmp_path):
    p = tmp_path / "a.txt"
    p.write_bytes(b"hello world")
    h1 = hashing.hash_file(p)
    h2 = hashing.hash_file(p)
    assert h1 == h2
    assert h1["sha256"] == (
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    )


def test_verify_detects_modification(tmp_path):
    p = tmp_path / "a.txt"
    p.write_bytes(b"original content")
    expected = hashing.hash_file(p)
    assert all(hashing.verify_file(p, expected).values())

    p.write_bytes(b"tampered content")
    result = hashing.verify_file(p, expected)
    assert not any(result.values())


def test_extension_magic_mismatch(tmp_path):
    """A PNG body renamed as .jpg should trip the disguise indicator."""
    p = tmp_path / "fake.jpg"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    meta = metadata.extract(p)
    findings = tamper.analyze(meta)
    codes = [f["code"] for f in findings]
    assert "EXT_MAGIC_MISMATCH" in codes


def test_empty_file_flagged(tmp_path):
    p = tmp_path / "empty.pdf"
    p.write_bytes(b"")
    findings = tamper.analyze(metadata.extract(p))
    assert any(f["code"] == "EMPTY_FILE" for f in findings)


def test_custody_chain_integrity(tmp_path):
    ledger_path = tmp_path / "custody.jsonl"
    ledger = CustodyLedger(ledger_path)
    ledger.append("REGISTER", "exhibit-A", {"note": "first"})
    ledger.append("ACCESS", "exhibit-A", {"note": "second"})
    ledger.append("NOTE", "exhibit-A", {"note": "third"})

    report = ledger.verify()
    assert report["ok"] is True
    assert report["entries_checked"] == 3


def test_custody_chain_detects_tampering(tmp_path):
    """Manually edit a ledger entry and ensure verify() catches it."""
    ledger_path = tmp_path / "custody.jsonl"
    ledger = CustodyLedger(ledger_path)
    ledger.append("REGISTER", "exhibit-A", {"value": "clean"})
    ledger.append("ACCESS", "exhibit-A", {"value": "clean"})
    ledger.append("NOTE", "exhibit-A", {"value": "clean"})

    # Tamper: rewrite the middle entry's details but leave the hash chain alone.
    lines = ledger_path.read_text().splitlines()
    middle = json.loads(lines[1])
    middle["details"]["value"] = "TAMPERED"
    lines[1] = json.dumps(middle, sort_keys=True)
    ledger_path.write_text("\n".join(lines) + "\n")

    report = ledger.verify()
    assert report["ok"] is False
    assert report["broken_at"] == 1


def test_register_then_verify_roundtrip(tmp_path, monkeypatch):
    """Drive the CLI end-to-end."""
    import evidence_tool

    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"some binary evidence \x00\x01\x02")
    ledger_path = tmp_path / "custody.jsonl"

    rc = evidence_tool.main([
        "--ledger", str(ledger_path), "register", str(evidence),
    ])
    assert rc == 0

    # Untampered file: verify must pass.
    rc = evidence_tool.main([
        "--ledger", str(ledger_path), "verify", str(evidence),
    ])
    assert rc == 0

    # Tamper with the file.
    evidence.write_bytes(b"tampered!")
    rc = evidence_tool.main([
        "--ledger", str(ledger_path), "verify", str(evidence),
    ])
    assert rc == 1


if __name__ == "__main__":
    # Minimal runner so this file works without pytest installed.
    import tempfile, traceback
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        with tempfile.TemporaryDirectory() as d:
            try:
                # Best-effort: only pass tmp_path if the test takes it.
                argcount = t.__code__.co_argcount
                if argcount == 0:
                    t()
                elif argcount == 1:
                    t(Path(d))
                else:
                    class _MP:
                        def setattr(self, *a, **k): pass
                    t(Path(d), _MP())
                print(f"PASS  {t.__name__}")
            except Exception:
                failed += 1
                print(f"FAIL  {t.__name__}")
                traceback.print_exc()
    sys.exit(1 if failed else 0)
