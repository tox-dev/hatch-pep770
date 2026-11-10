from __future__ import annotations

import base64
import hashlib
import re
import zipfile
from io import BytesIO
from itertools import starmap
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom import SbomError
from python_sbom._model._inputs import BundledWheel, RecordRow
from python_sbom._wheel._bundled import read_bundled_wheels

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from conftest import WriteWheel

_INIT: Final[str] = "pip/__init__.py"
_METADATA: Final[str] = "pip-1.0.dist-info/METADATA"
_PIP: Final[dict[str, bytes]] = {_INIT: b"", _METADATA: b"Name: pip\nVersion: 1.0\n"}


# defined before the parametrized cases below, which build their RECORD rows with it at import time
def row(path: str, content: bytes, algorithm: str = "sha256", *, encoded: str = "", size: int | None = None) -> str:
    encoded = encoded or base64.urlsafe_b64encode(hashlib.new(algorithm, content).digest()).rstrip(b"=").decode()
    return f"{path},{algorithm}={encoded},{len(content) if size is None else size}\n"


_METADATA_ROW: Final[str] = row(_METADATA, _PIP[_METADATA])
_RECORD_ROW: Final[str] = "pip-1.0.dist-info/RECORD,,\n"


def test_bundled_wheel(tmp_path: Path, write_wheel: WriteWheel) -> None:
    wheel = write_wheel(
        tmp_path / "src" / "pip-1.0-py3-none-any.whl",
        {
            **_PIP,
            "pip/_vendor/vendor.txt": b"# pinned\n\nurllib3==1.26.4  # http\n",
            "pip/_vendor/rich-13.0.dist-info/METADATA": b"Name: rich\nVersion: 13.0\n",
        },
    )
    bundled = _bundled(wheel.read_bytes(), "src/pip-1.0-py3-none-any.whl")
    assert (bundled.path, bundled.sha256, bundled.metadata_name, bundled.metadata.name, bundled.files[0]) == (
        "src/pip-1.0-py3-none-any.whl",
        hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "pip-1.0.dist-info/METADATA",
        "pip",
        RecordRow(path="pip/__init__.py", algorithm="SHA-256", digest=hashlib.sha256(b"").hexdigest(), size="0"),
    )
    assert [(source, metadata.raw) for source, metadata in bundled.vendored] == [
        ("pip/_vendor/vendor.txt", {"name": "urllib3", "version": "1.26.4"}),
        ("pip/_vendor/rich-13.0.dist-info/METADATA", {"name": "rich", "version": "13.0"}),
    ]


@pytest.mark.parametrize(
    ("files", "message"),
    [
        pytest.param(
            {"pip/__init__.py": b""},
            r"is not a wheel: Wheel doesn't contain exactly one \.dist-info directory",
            id="no-dist-info",
        ),
        pytest.param({"pip-1.0.dist-info/WHEEL": b""}, "has no pip-1.0.dist-info/METADATA", id="no-metadata"),
        pytest.param(
            {"aaa-0.dist-info/METADATA": b"Name: aaa\nVersion: 0\n", **_PIP},
            r"is not a wheel: Wheel doesn't contain exactly one \.dist-info directory",
            id="two-dist-info",
        ),
        pytest.param({"pip-1.0.dist-info/METADATA": b"Name: pip\n"}, "METADATA lacks Name or Version", id="no-version"),
        pytest.param(
            {"pip-1.0.dist-info/METADATA": _PIP["pip-1.0.dist-info/METADATA"]},
            "has no pip-1.0.dist-info/RECORD",
            id="no-record",
        ),
        pytest.param(
            {"pip-1.0.dist-info/METADATA": b"Name: pip\nVersion: 1.0\n" + b" " * 16 * 1024 * 1024},
            "METADATA is over the 16777216 byte limit",
            id="oversized-metadata",
        ),
        pytest.param(
            {**_PIP, "pip-1.0.dist-info/RECORD": b"\n" * (16 * 1024 * 1024 + 1)},
            "RECORD is over the 16777216 byte limit",
            id="oversized-record",
        ),
    ],
)
def test_malformed_bundled_wheel(
    tmp_path: Path, write_wheel: WriteWheel, files: Mapping[str, bytes], message: str
) -> None:
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", files, record=False)
    with pytest.raises(SbomError, match=message):
        _bundled(wheel.read_bytes(), "pip-1.0-py3-none-any.whl")


@pytest.mark.parametrize(
    ("name", "message"),
    [
        pytest.param("pip.whl", "Not a valid wheel filename: pip.whl", id="unparsable"),
        pytest.param(
            "other-1.0-py3-none-any.whl", r"Wheel \.dist-info directory doesn't match wheel filename", id="other"
        ),
    ],
)
def test_bundled_wheel_file_name_names_the_project(
    tmp_path: Path, write_wheel: WriteWheel, name: str, message: str
) -> None:
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", _PIP)
    with pytest.raises(SbomError, match=f"bundled wheel {name} is not a wheel: {message}"):
        _bundled(wheel.read_bytes(), name)


def test_corrupt_bundled_wheel() -> None:
    with pytest.raises(SbomError, match=r"bundled wheel pip\.whl is not a valid zip archive"):
        _bundled(b"not a zip", "pip.whl")


def test_bundled_wheel_with_duplicate_member(tmp_path: Path) -> None:
    # installers extract the first copy, so a RECORD that hashes the second one would hide the installed code
    with zipfile.ZipFile(wheel := tmp_path / "pip-1.0-py3-none-any.whl", "w") as archive:
        archive.writestr(_INIT, b"import os\n")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr(_INIT, b"")
        archive.writestr(_METADATA, _PIP[_METADATA])
        archive.writestr("pip-1.0.dist-info/RECORD", f"{row(_INIT, b'')}{_METADATA_ROW}")
    with pytest.raises(SbomError, match=f"holds more than one member named {_INIT}, ignoring case"):
        _bundled(wheel.read_bytes(), "pip-1.0-py3-none-any.whl")


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        pytest.param("sha256", "SHA-256", id="sha256"),
        pytest.param("sha384", "SHA-384", id="sha384"),
        pytest.param("sha512", "SHA-512", id="sha512"),
    ],
)
def test_bundled_wheel_record_algorithm(tmp_path: Path, write_wheel: WriteWheel, algorithm: str, expected: str) -> None:
    record = "".join(row(path, content, algorithm) for path, content in _PIP.items()) + _RECORD_ROW
    files = {**_PIP, "pip-1.0.dist-info/RECORD": record.encode()}
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", files, record=False)
    assert [
        (file.path, file.algorithm, file.digest)
        for file in _bundled(wheel.read_bytes(), "pip-1.0-py3-none-any.whl").files
    ] == [(path, expected, hashlib.new(algorithm, content).hexdigest()) for path, content in _PIP.items()]


@pytest.mark.parametrize(
    ("record", "message"),
    [
        pytest.param(
            f"{_INIT},sha256=x\n", "RECORD does not parse: Row Index 0: expected 3 elements, got 2", id="columns"
        ),
        pytest.param(
            f"{_METADATA_ROW}\n{_RECORD_ROW}",
            "RECORD does not parse: Row Index 1: expected 3 elements, got 0",
            id="blank-line",
        ),
        pytest.param(
            f"{_INIT},,0\n{_METADATA_ROW}{_RECORD_ROW}",
            f"RECORD disagrees with the wheel: hash / size of {_INIT} is not included in RECORD",
            id="no-digest",
        ),
        pytest.param(
            f"{row(_INIT, b'')}{_METADATA_ROW}",
            "RECORD disagrees with the wheel: pip-1.0.dist-info/RECORD is not mentioned in RECORD",
            id="record-not-recorded",
        ),
        pytest.param(
            f"{row(_INIT, b'', 'sha224')}{_METADATA_ROW}{_RECORD_ROW}",
            f"RECORD row for {_INIT}: unknown hash algorithm 'sha224'",
            id="algorithm-cyclonedx-lacks",
        ),
        # installer would call digest() without the length shake_128 needs and raise a TypeError
        pytest.param(
            f"{_INIT},shake_128=AAAA,0\n{_METADATA_ROW}{_RECORD_ROW}",
            f"RECORD row for {_INIT}: unknown hash algorithm 'shake_128'",
            id="algorithm-needing-a-length",
        ),
        pytest.param(_METADATA_ROW, f"RECORD lacks a digest for {_INIT}", id="member-not-recorded"),
        pytest.param(
            f"{row(_INIT, b'', encoded='A' * 43)}{row(_INIT, b'')}{_METADATA_ROW}",
            f"RECORD lists {_INIT} more than once",
            id="listed-twice",
        ),
        pytest.param(
            f"{row(_INIT, b'')}{row(_INIT, b'', 'sha512', encoded='A' * 86)}{_METADATA_ROW}",
            f"RECORD lists {_INIT} more than once",
            id="listed-twice-by-other-algorithm",
        ),
        pytest.param(
            f"{row(_INIT, b'')}{row('pip/ghost.py', b'', 'md5', size=99)}{_METADATA_ROW}",
            "RECORD lists pip/ghost.py, which the wheel does not hold",
            id="recorded-not-member",
        ),
        pytest.param(
            f"{row(_INIT, b'', size=999999)}{_METADATA_ROW}{_RECORD_ROW}",
            f"RECORD disagrees with the wheel: hash / size of {_INIT} didn't match RECORD",
            id="size-mismatch",
        ),
        pytest.param(
            f"{row(_INIT, b'', 'sha512', encoded='A' * 86)}{_METADATA_ROW}{_RECORD_ROW}",
            f"RECORD disagrees with the wheel: hash / size of {_INIT} didn't match RECORD",
            id="digest-mismatch",
        ),
    ],
)
def test_record_disagrees_with_wheel(tmp_path: Path, write_wheel: WriteWheel, record: str, message: str) -> None:
    files = {**_PIP, "pip-1.0.dist-info/RECORD": record.encode()}
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", files, record=False)
    with pytest.raises(SbomError, match=message):
        _bundled(wheel.read_bytes(), "pip-1.0-py3-none-any.whl")


def test_record_signatures_need_no_row(tmp_path: Path, write_wheel: WriteWheel) -> None:
    record = "".join(starmap(row, _PIP.items())) + _RECORD_ROW
    files = {**_PIP, "pip-1.0.dist-info/RECORD": record.encode(), "pip-1.0.dist-info/RECORD.jws": b"{}"}
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", files, record=False)
    assert [file.path for file in _bundled(wheel.read_bytes(), "pip-1.0-py3-none-any.whl").files] == list(_PIP)


@pytest.mark.parametrize(
    "signature",
    [
        pytest.param("pip-1.0.dist-info/sub/RECORD.jws", id="nested"),
        pytest.param("pip-1.0.dist-info/../pip/RECORD.p7s", id="parent"),
    ],
)
def test_signature_away_from_record_needs_a_row(tmp_path: Path, write_wheel: WriteWheel, signature: str) -> None:
    # installer lets these go unlisted, though a signature only sits beside RECORD
    record = "".join(starmap(row, _PIP.items())) + _RECORD_ROW
    files = {**_PIP, "pip-1.0.dist-info/RECORD": record.encode(), signature: b"import os\n"}
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", files, record=False)
    with pytest.raises(SbomError, match=f"RECORD lacks a digest for {re.escape(signature)}"):
        _bundled(wheel.read_bytes(), "pip-1.0-py3-none-any.whl")


def test_vendored_metadata_needs_name_and_version(tmp_path: Path, write_wheel: WriteWheel) -> None:
    files = {**_PIP, "pip/_vendor/rich-13.0.dist-info/METADATA": b"Metadata-Version: 2.1\n"}
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", files)
    with pytest.raises(SbomError, match=r"pip/_vendor/rich-13\.0\.dist-info/METADATA lacks Name or Version"):
        _bundled(wheel.read_bytes(), "pip-1.0-py3-none-any.whl")


@pytest.mark.parametrize(
    ("manifest", "message"),
    [
        pytest.param(b"urllib3 ==\n", "does not parse: urllib3 ==", id="unparsable"),
        pytest.param(b"urllib3>=1\n", "pins no one exact version: urllib3>=1", id="range"),
        pytest.param(b"urllib3==1.*\n", "pins no one exact version: urllib3==1.*", id="wildcard"),
        pytest.param(b"urllib3==1,!=1.1\n", "pins no one exact version: urllib3==1,!=1.1", id="two-specifiers"),
    ],
)
def test_vendor_manifest_needs_exact_pins(
    tmp_path: Path, write_wheel: WriteWheel, manifest: bytes, message: str
) -> None:
    wheel = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", {**_PIP, "pip/_vendor/vendor.txt": manifest})
    with pytest.raises(SbomError, match=message):
        _bundled(wheel.read_bytes(), "pip-1.0-py3-none-any.whl")


def _bundled(data: bytes, path: str) -> BundledWheel:
    return read_bundled_wheels([path], lambda _: BytesIO(data))[0]


def test_bundled_wheels_come_in_the_order_given(tmp_path: Path, write_wheel: WriteWheel) -> None:
    # read side by side, yet reported in order, the first broken wheel's error included
    good = write_wheel(tmp_path / "pip-1.0-py3-none-any.whl", _PIP).read_bytes()
    wheels = {"pip-1.0-py3-none-any.whl": good, "b.whl": b"not a zip", "c.whl": b"neither"}
    paths = ["pip-1.0-py3-none-any.whl", "b.whl", "c.whl"]
    assert [bundled.path for bundled in read_bundled_wheels(paths[:1] * 2, lambda name: BytesIO(wheels[name]))] == [
        paths[0],
        paths[0],
    ]
    with pytest.raises(SbomError, match=r"^bundled wheel b\.whl is not a valid zip archive"):
        read_bundled_wheels(paths, lambda name: BytesIO(wheels[name]))
