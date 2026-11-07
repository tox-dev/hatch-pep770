from __future__ import annotations

import hashlib

import pytest

from python_sbom._errors import SbomError
from python_sbom._wheel._record import decode_digest


@pytest.mark.parametrize(
    ("digest", "expected"),
    [
        pytest.param(
            "sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
            ("SHA-256", hashlib.sha256(b"").hexdigest()),
            id="sha256",
        ),
        pytest.param(
            "md5=1B2M2Y8AsgTpgAmY7PhCfg", ("MD5", hashlib.md5(b"", usedforsecurity=False).hexdigest()), id="md5"
        ),
    ],
)
def test_decode_digest(digest: str, expected: tuple[str, str]) -> None:
    assert decode_digest(digest, "w") == expected


@pytest.mark.parametrize(
    ("digest", "message"),
    [
        pytest.param("blake2b=AAAA", "w: unknown hash algorithm 'blake2b'", id="algorithm"),
        pytest.param("sha256=abcde", "w: digest 'abcde' is not urlsafe base64", id="base64"),
    ],
)
def test_decode_digest_rejects(digest: str, message: str) -> None:
    with pytest.raises(SbomError, match=message):
        decode_digest(digest, "w")
