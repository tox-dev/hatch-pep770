from __future__ import annotations

from python_sbom import _core


def decode_digest(digest: str, where: str) -> tuple[str, str]:
    # installer checks RECORD digests as urlsafe base64 under any hashlib name, while CycloneDX takes hex under its own
    # names for a few algorithms
    return _core.decode_digest(digest, where)


__all__ = [
    "decode_digest",
]
