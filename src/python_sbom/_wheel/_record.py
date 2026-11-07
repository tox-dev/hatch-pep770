from __future__ import annotations

import base64
import binascii
from typing import Final

from python_sbom._errors import WheelError

# the algorithms a wheel RECORD may name, as CycloneDX spells them
_ALGORITHMS: Final[dict[str, str]] = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
}


def decode_digest(digest: str, where: str) -> tuple[str, str]:
    # installer checks RECORD digests as urlsafe base64 under any hashlib name, while CycloneDX takes hex under its own
    # names for a few algorithms
    name, _, encoded = digest.partition("=")
    if (algorithm := _ALGORITHMS.get(name)) is None:
        msg = f"{where}: unknown hash algorithm {name!r}"
        raise WheelError(msg)
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except binascii.Error as error:
        msg = f"{where}: digest {encoded!r} is not urlsafe base64"
        raise WheelError(msg) from error
    return algorithm, raw.hex()


__all__ = [
    "decode_digest",
]
