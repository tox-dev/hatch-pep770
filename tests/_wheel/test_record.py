from __future__ import annotations

import hashlib
from typing import Final

import pytest

from python_sbom._errors import WheelError
from python_sbom._model._inputs import RecordRow
from python_sbom._wheel._record import decode_digest, parse_record, record_line

# the SHA-256 of b"", urlsafe base64 without padding
_EMPTY: Final[str] = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"


def test_parse_record_row() -> None:
    assert parse_record(f"pkg/__init__.py,sha256={_EMPTY},0\n", "w") == [
        RecordRow(path="pkg/__init__.py", algorithm="SHA-256", digest=hashlib.sha256(b"").hexdigest(), size="0")
    ]


def test_parse_record_unquotes_csv() -> None:
    assert [row.path for row in parse_record(f'"pkg/a,b.py",sha256={_EMPTY},0\n', "w")] == ["pkg/a,b.py"]


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("\n", id="blank"),
        pytest.param("pkg-1.0.dist-info/RECORD,,\n", id="record"),
        pytest.param("pkg-1.0.dist-info/RECORD.jws,,\n", id="jws-signature"),
        pytest.param("pkg-1.0.dist-info/RECORD.p7s,,\n", id="p7s-signature"),
    ],
)
def test_parse_record_skips_rows_without_digest(text: str) -> None:
    assert parse_record(text, "w") == []


@pytest.mark.parametrize(
    ("text", "message"),
    [
        pytest.param("pkg/__init__.py,,0\n", "w: RECORD row 1 gives no digest for pkg/__init__.py", id="no-digest"),
        pytest.param("pkg/,,\n", "w: RECORD row 1 gives no digest for pkg/", id="directory"),
        pytest.param(f"pkg/__init__.py,sha256={_EMPTY}\n", "w: RECORD row 1 has 2 columns, not 3", id="two-columns"),
        pytest.param(f"a,sha256={_EMPTY},0,extra\n", "w: RECORD row 1 has 4 columns, not 3", id="four-columns"),
        pytest.param("\npkg/__init__.py\n", "w: RECORD row 2 has 1 columns, not 3", id="row-number"),
    ],
)
def test_parse_record_rejects_row(text: str, message: str) -> None:
    with pytest.raises(WheelError, match=message):
        parse_record(text, "w")


@pytest.mark.parametrize(
    ("digest", "expected"),
    [
        pytest.param(f"sha256={_EMPTY}", ("SHA-256", hashlib.sha256(b"").hexdigest()), id="sha256"),
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
    with pytest.raises(WheelError, match=message):
        decode_digest(digest, "w")


def test_record_line() -> None:
    assert record_line("pkg/__init__.py", b"") == f"pkg/__init__.py,sha256={_EMPTY},0"
