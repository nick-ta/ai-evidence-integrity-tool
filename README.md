# AI Evidence Integrity Tool

Forensic pipeline for detecting tampering in digital evidence — metadata analysis, hash verification, and chain-of-custody logging.

## What it does

1. **Hash verification** — Computes MD5, SHA-1, SHA-256, and SHA-512 of an evidence file so any later modification (even a single byte) can be detected.
2. **Metadata analysis** — Extracts filesystem timestamps, magic-byte file type, extension, and (for images) EXIF data.
3. **Tamper detection** — Runs heuristic checks for common manipulation indicators:
   - extension/magic-byte mismatch (file renamed to disguise type)
   - EXIF `Software` tag matching known editors (Photoshop, GIMP, Lightroom…)
   - EXIF `Software` tag matching known AI image generators (Stable Diffusion, Midjourney, DALL·E…)
   - JPEG with no camera fields or original-capture timestamp (likely re-encoded / screenshotted)
   - filesystem modification time *before* EXIF capture time (physically impossible)
   - zero-byte evidence files
4. **Chain-of-custody ledger** — Every action is appended to a hash-chained JSONL ledger. Each entry includes the SHA-256 of the previous entry; altering or deleting any past entry breaks the chain for every entry that follows it. The `audit` command walks the chain and reports the first broken link.

## Install

```sh
pip install -r requirements.txt
```

Only dependency is Pillow (used for EXIF extraction). Everything else is stdlib.

## CLI usage

```sh
# Register a piece of evidence: hash it, fingerprint it, run tamper checks,
# and write a REGISTER entry to the custody ledger.
python evidence_tool.py register path/to/photo.jpg

# Re-verify the file later — any modification will surface as a hash mismatch.
python evidence_tool.py verify path/to/photo.jpg

# Triage-only tamper analysis (no ledger write).
python evidence_tool.py analyze path/to/photo.jpg

# Inspect the ledger.
python evidence_tool.py ledger

# Audit the ledger's hash chain — confirms the log itself has not been tampered with.
python evidence_tool.py audit

# Record a free-text observation or handoff.
python evidence_tool.py note photo.jpg "Transferred to Det. Chen on 2026-05-23"
```

Use `--ledger PATH` to point at a non-default custody file (default: `./custody.jsonl`).

## Project layout

```
evidence_tool.py      # CLI entrypoint
core/
  hashing.py          # Multi-algorithm streaming file hashing + verification
  metadata.py         # Filesystem + magic-byte + EXIF extraction
  tamper.py           # Heuristic tampering indicators
  custody.py          # Hash-chained append-only custody ledger
tests/
  test_integrity.py   # End-to-end tests (pytest-compatible; also runnable directly)
```

## Testing

```sh
python -m pytest tests/        # or:  python tests/test_integrity.py
```

## Caveats — please read before using in any real proceeding

- Tamper indicators are *evidence of possible manipulation*, not proof. A human forensic examiner still has to weigh each finding.
- The ledger is tamper-*evident*, not tamper-*proof*. An attacker with write access can rewrite the entire chain. For a real deployment, the ledger should be written to WORM (write-once-read-many) media, replicated to an append-only datastore, and/or co-signed by an external timestamping authority (RFC 3161, OpenTimestamps, etc.).
- On Windows, `st_ctime` is the file creation time. On POSIX it is the inode-change time. The timestamp-paradox check is conservative but be aware of the platform difference.
