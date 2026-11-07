from __future__ import annotations

import hashlib

import pytest

from python_sbom._errors import SbomError
from python_sbom._model._inputs import RecordRow
from python_sbom._wheel._record import record_rows


@pytest.mark.parametrize(
    ("digest", "algorithm", "expected"),
    [
        pytest.param(
            "sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
            "SHA-256",
            hashlib.sha256(b"").hexdigest(),
            id="sha256",
        ),
        pytest.param(
            "md5=1B2M2Y8AsgTpgAmY7PhCfg", "MD5", hashlib.md5(b"", usedforsecurity=False).hexdigest(), id="md5"
        ),
    ],
)
def test_record_rows_decode_digests(digest: str, algorithm: str, expected: str) -> None:
    assert record_rows([("a.py", digest, "0")], "w") == [
        RecordRow(path="a.py", algorithm=algorithm, digest=expected, size="0")
    ]


def test_record_rows_skip_unhashed() -> None:
    assert record_rows([("w.dist-info/RECORD", "", "")], "w") == []


@pytest.mark.parametrize(
    ("digest", "message"),
    [
        pytest.param("blake2b=AAAA", "w: RECORD row for a.py: unknown hash algorithm 'blake2b'", id="algorithm"),
        pytest.param("sha256=abcde", "w: RECORD row for a.py: digest 'abcde' is not urlsafe base64", id="base64"),
    ],
)
def test_record_rows_reject_digests(digest: str, message: str) -> None:
    with pytest.raises(SbomError, match=message):
        record_rows([("a.py", digest, "0")], "w")
