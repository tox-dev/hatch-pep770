from __future__ import annotations

import base64
import binascii
from itertools import starmap
from typing import TYPE_CHECKING, Final

from installer.records import RecordEntry

from python_sbom._errors import SbomError
from python_sbom._model._inputs import RecordRow

if TYPE_CHECKING:
    from collections.abc import Iterable

# the algorithms a wheel RECORD may name, as CycloneDX spells them
_ALGORITHMS: Final[dict[str, str]] = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
}


def record_rows(rows: Iterable[tuple[str, str, str]], where: str) -> list[RecordRow]:
    # the rows with a digest, as the SBOM lists them: RECORD's own row has none, nor has a file an installer left
    # unhashed; installer's InvalidRecordEntry passes to the caller, which knows what a malformed row means there
    found: Final[list[RecordRow]] = []
    for entry in starmap(RecordEntry.from_elements, rows):
        if entry.hash_ is None:
            continue
        algorithm, digest = decode_digest(str(entry.hash_), f"{where}: RECORD row for {entry.path}")
        found.append(RecordRow(path=entry.path, algorithm=algorithm, digest=digest, size=str(entry.size)))
    return found


def decode_digest(digest: str, where: str) -> tuple[str, str]:
    # installer checks RECORD digests as urlsafe base64 under any hashlib name, while CycloneDX takes hex under its own
    # names for a few algorithms
    name, _, encoded = digest.partition("=")
    if (algorithm := _ALGORITHMS.get(name)) is None:
        msg = f"{where}: unknown hash algorithm {name!r}"
        raise SbomError(msg)
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except binascii.Error as error:
        msg = f"{where}: digest {encoded!r} is not urlsafe base64"
        raise SbomError(msg) from error
    return algorithm, raw.hex()


__all__ = [
    "decode_digest",
    "record_rows",
]
