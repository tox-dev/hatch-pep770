from __future__ import annotations

import base64
import binascii
import csv
import hashlib
from io import StringIO
from typing import Final

from python_sbom._errors import WheelError
from python_sbom._model._inputs import RecordRow

# the algorithms a wheel RECORD may name, as CycloneDX spells them
_ALGORITHMS: Final[dict[str, str]] = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
}


def parse_record(text: str, where: str) -> list[RecordRow]:
    # the row of RECORD itself has no digest and is left out
    rows: Final[list[RecordRow]] = []
    for number, columns in enumerate(csv.reader(StringIO(text, newline="")), start=1):
        if not columns:
            continue
        if len(columns) != 3:  # ruff: ignore[magic-value-comparison] # path, digest and size, as the wheel specification lays out a row
            msg = f"{where}: RECORD row {number} has {len(columns)} columns, not 3"
            raise WheelError(msg)
        path, digest, size = columns
        if digest:
            algorithm, hexdigest = decode_digest(digest, f"{where}: RECORD row {number}")
            rows.append(RecordRow(path=path, algorithm=algorithm, digest=hexdigest, size=size))
    return rows


def decode_digest(digest: str, where: str) -> tuple[str, str]:
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


def record_line(name: str, content: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
    return f"{name},sha256={encoded},{len(content)}"


__all__ = [
    "decode_digest",
    "parse_record",
    "record_line",
]
