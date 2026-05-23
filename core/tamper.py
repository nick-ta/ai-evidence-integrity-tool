"""Heuristic tampering detection.

These are *indicators*, not proof. A forensic examiner still has to weigh
each finding. Each indicator has a severity:
  - high:   strongly suggests tampering or misrepresentation
  - medium: worth investigating; could be benign
  - low:    informational anomaly
"""
from __future__ import annotations

import datetime as dt
from typing import Any

# Image editors whose presence in EXIF Software tag indicates post-capture editing.
EDITOR_SIGNATURES = (
    "adobe photoshop", "photoshop", "gimp", "lightroom", "affinity",
    "paint.net", "pixelmator", "luminar", "snapseed", "facetune",
)

# Generative AI signatures that may appear in metadata.
AI_GENERATION_SIGNATURES = (
    "stable diffusion", "midjourney", "dall-e", "dalle", "openai",
    "firefly", "imagen", "comfyui", "automatic1111", "invokeai",
)


def _parse_exif_datetime(value: str) -> dt.datetime | None:
    """EXIF datetimes are 'YYYY:MM:DD HH:MM:SS'."""
    if not isinstance(value, str):
        return None
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y:%m:%d %H:%M:%S%z"):
        try:
            return dt.datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    return None


def analyze(metadata: dict[str, Any]) -> list[dict[str, str]]:
    """Run all indicator checks against an extracted metadata bundle.

    Returns a list of {severity, code, message} findings. An empty list
    means no indicators of tampering were detected (which is NOT a guarantee
    the file is authentic).
    """
    findings: list[dict[str, str]] = []
    fs = metadata.get("filesystem") or {}
    exif = metadata.get("exif") or {}
    ext_mime = metadata.get("extension_mime")
    magic_mime = metadata.get("magic_mime")

    # 1. Extension/magic-byte mismatch — classic file disguise.
    if ext_mime and magic_mime and ext_mime != magic_mime:
        findings.append({
            "severity": "high",
            "code": "EXT_MAGIC_MISMATCH",
            "message": (
                f"File extension implies {ext_mime} but file signature is {magic_mime}. "
                "The file may have been renamed to disguise its true type."
            ),
        })
    elif ext_mime and not magic_mime:
        findings.append({
            "severity": "low",
            "code": "UNKNOWN_SIGNATURE",
            "message": f"Extension suggests {ext_mime} but no known signature was matched.",
        })

    # 2. Known editor in EXIF Software tag.
    software = str(exif.get("Software", "")).lower()
    if software:
        for sig in EDITOR_SIGNATURES:
            if sig in software:
                findings.append({
                    "severity": "high",
                    "code": "EDITOR_SIGNATURE",
                    "message": (
                        f"EXIF Software tag is '{exif.get('Software')}'. "
                        "Image was processed by editing software after capture."
                    ),
                })
                break
        for sig in AI_GENERATION_SIGNATURES:
            if sig in software:
                findings.append({
                    "severity": "high",
                    "code": "AI_GENERATED",
                    "message": (
                        f"EXIF Software tag '{exif.get('Software')}' matches a known "
                        "AI image-generation tool. The image may be synthetic."
                    ),
                })
                break

    # 3. Missing camera fields on an image that claims to be a photograph.
    if metadata.get("extension", "").lower() in (".jpg", ".jpeg") and exif is not None:
        has_make = "Make" in exif
        has_model = "Model" in exif
        has_datetime = "DateTimeOriginal" in exif or "DateTime" in exif
        if not (has_make or has_model or has_datetime):
            findings.append({
                "severity": "medium",
                "code": "EXIF_STRIPPED",
                "message": (
                    "JPEG has no camera make/model and no original-capture timestamp. "
                    "EXIF may have been stripped (common when re-encoding or screenshotting)."
                ),
            })

    # 4. EXIF capture time vs filesystem modification time.
    exif_dt = _parse_exif_datetime(exif.get("DateTimeOriginal") or exif.get("DateTime") or "")
    if exif_dt and fs.get("modified_utc"):
        try:
            fs_mod = dt.datetime.fromisoformat(fs["modified_utc"]).replace(tzinfo=None)
            delta = fs_mod - exif_dt
            # File modified BEFORE its claimed capture time → impossible without tampering.
            if delta.total_seconds() < -60:
                findings.append({
                    "severity": "high",
                    "code": "TIMESTAMP_PARADOX",
                    "message": (
                        f"Filesystem modification time ({fs_mod.isoformat()}) predates "
                        f"EXIF capture time ({exif_dt.isoformat()}). This is physically "
                        "impossible without tampering or a clock reset."
                    ),
                })
            elif delta.total_seconds() > 7 * 24 * 3600:
                findings.append({
                    "severity": "low",
                    "code": "TIMESTAMP_GAP",
                    "message": (
                        f"File was modified {delta.days} days after its EXIF capture time. "
                        "This is common when copying files but worth noting."
                    ),
                })
        except (ValueError, TypeError):
            pass

    # 5. Suspicious zero-size or unusually tiny evidence files.
    size = fs.get("size_bytes", 0)
    if size == 0:
        findings.append({
            "severity": "high",
            "code": "EMPTY_FILE",
            "message": "File is zero bytes. Evidence content is missing.",
        })

    return findings
