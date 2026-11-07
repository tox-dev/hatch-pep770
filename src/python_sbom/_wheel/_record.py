from __future__ import annotations

import base64
import binascii
import csv
import hashlib
from io import StringIO
from pathlib import PurePosixPath
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
# the hashlib name of each algorithm, by its CycloneDX spelling
HASHLIB_NAMES: Final[dict[str, str]] = {cyclonedx: name for name, cyclonedx in _ALGORITHMS.items()}
# the files of a .dist-info the wheel specification leaves without a digest: RECORD and its signatures
UNHASHED: Final[frozenset[str]] = frozenset({"RECORD", "RECORD.jws", "RECORD.p7s"})


def parse_record(text: str, where: str) -> list[RecordRow]:
    # the rows without a digest, which only RECORD and its signatures may have, are left out
    rows: Final[list[RecordRow]] = []
    for number, columns in enumerate(csv.reader(StringIO(text, newline="")), start=1):
        match columns:
            case []:
                pass
            case [path, "", _] if PurePosixPath(path).name in UNHASHED:
                pass
            case [path, "", _]:
                msg = f"{where}: RECORD row {number} gives no digest for {path}"
                raise WheelError(msg)
            case [path, digest, size]:
                algorithm, hexdigest = decode_digest(digest, f"{where}: RECORD row {number}")
                rows.append(RecordRow(path=path, algorithm=algorithm, digest=hexdigest, size=size))
            case _:
                msg = f"{where}: RECORD row {number} has {len(columns)} columns, not 3"
                raise WheelError(msg)
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
    "HASHLIB_NAMES",
    "UNHASHED",
    "decode_digest",
    "parse_record",
    "record_line",
]
