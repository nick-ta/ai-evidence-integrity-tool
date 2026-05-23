"""Cryptographic hashing for evidence files.

Forensic standard practice computes multiple hashes simultaneously so that
even if one algorithm is later compromised, the others still anchor integrity.
"""
import hashlib
from pathlib import Path

ALGORITHMS = ("md5", "sha1", "sha256", "sha512")
CHUNK = 1024 * 1024  # 1 MiB streaming read


def hash_file(path: str | Path, algorithms: tuple[str, ...] = ALGORITHMS) -> dict[str, str]:
    """Return a dict of {algorithm: hex_digest} for the given file.

    Streams the file in chunks so it works on multi-GB evidence.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Not a file: {p}")

    hashers = {alg: hashlib.new(alg) for alg in algorithms}
    with p.open("rb") as f:
        while chunk := f.read(CHUNK):
            for h in hashers.values():
                h.update(chunk)
    return {alg: h.hexdigest() for alg, h in hashers.items()}


def verify_file(path: str | Path, expected: dict[str, str]) -> dict[str, bool]:
    """Re-hash a file and compare against expected digests.

    Returns {algorithm: matched?}. A False anywhere means the file changed
    since the expected hash was recorded.
    """
    actual = hash_file(path, tuple(expected.keys()))
    return {alg: actual[alg].lower() == expected[alg].lower() for alg in expected}
