"""Metadata + file-signature extraction.

Extracts filesystem timestamps, magic-byte file type, and EXIF data (for
images). The Pillow dependency is optional — non-image evidence still gets
filesystem and signature analysis.
"""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
from typing import Any

try:
    from PIL import Image, ExifTags
    _HAS_PIL = True
except ImportError:  # pragma: no cover
    _HAS_PIL = False


# Well-known magic-byte signatures. Order matters for prefixes.
MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"BM", "image/bmp"),
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),  # also docx/xlsx/pptx
    (b"\x1f\x8b", "application/gzip"),
    (b"ID3", "audio/mpeg"),
    (b"\xff\xfb", "audio/mpeg"),
    (b"RIFF", "container/riff"),  # avi/wav — check sub-header
    (b"\x00\x00\x00\x18ftyp", "video/mp4"),
    (b"\x00\x00\x00\x20ftyp", "video/mp4"),
]

EXTENSION_MIME: dict[str, str] = {
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".pdf": "application/pdf",
    ".zip": "application/zip",
    ".docx": "application/zip", ".xlsx": "application/zip", ".pptx": "application/zip",
    ".gz": "application/gzip",
    ".mp3": "audio/mpeg",
    ".mp4": "video/mp4", ".m4v": "video/mp4", ".mov": "video/mp4",
    ".wav": "container/riff", ".avi": "container/riff",
}


def detect_magic(path: Path) -> str | None:
    """Return MIME type inferred from the first bytes of the file."""
    with path.open("rb") as f:
        header = f.read(32)
    for sig, mime in MAGIC_SIGNATURES:
        if header.startswith(sig):
            return mime
    return None


def filesystem_metadata(path: Path) -> dict[str, Any]:
    st = path.stat()
    return {
        "absolute_path": str(path.resolve()),
        "size_bytes": st.st_size,
        # Note: ctime is creation on Windows, inode-change on POSIX.
        "created_utc": dt.datetime.fromtimestamp(st.st_ctime, tz=dt.timezone.utc).isoformat(),
        "modified_utc": dt.datetime.fromtimestamp(st.st_mtime, tz=dt.timezone.utc).isoformat(),
        "accessed_utc": dt.datetime.fromtimestamp(st.st_atime, tz=dt.timezone.utc).isoformat(),
    }


def exif_metadata(path: Path) -> dict[str, Any] | None:
    """Return EXIF tags for an image, or None if not an image / no EXIF."""
    if not _HAS_PIL:
        return None
    try:
        with Image.open(path) as img:
            raw = img.getexif()
            if not raw:
                return {}
            tags: dict[str, Any] = {}
            for tag_id, value in raw.items():
                name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
                # Coerce bytes to strings so the result is JSON-serializable.
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace").strip("\x00")
                    except Exception:
                        value = value.hex()
                tags[name] = value
            return tags
    except Exception:
        return None


def extract(path: str | Path) -> dict[str, Any]:
    """Full metadata bundle for an evidence file."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Not a file: {p}")
    return {
        "filesystem": filesystem_metadata(p),
        "extension": p.suffix.lower(),
        "extension_mime": EXTENSION_MIME.get(p.suffix.lower()),
        "magic_mime": detect_magic(p),
        "exif": exif_metadata(p),
    }
