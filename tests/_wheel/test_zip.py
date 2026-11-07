from __future__ import annotations

import io
import struct
import tracemalloc
import zipfile
from contextlib import ExitStack
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from python_sbom._errors import SbomError
from python_sbom._wheel._zip import open_archive, read_member, sha256_hex

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.mark.parametrize(
    "names",
    [
        pytest.param(("a.py", "A.py"), id="case"),
        pytest.param(("pkg/a.py", "PKG/a.py"), id="directory-case"),
    ],
)
def test_open_archive_refuses_names_equal_ignoring_case(names: tuple[str, str]) -> None:
    message = f"w holds more than one member named {names[0].lower()}, ignoring case"
    with pytest.raises(SbomError, match=message), ExitStack() as stack:
        stack.enter_context(open_archive(zip_of(*((name, b"") for name in names)), "w"))


def zip_of(*members: tuple[str, bytes]) -> BytesIO:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in members:
            archive.writestr(name, content)
    return buffer


def test_open_archive_refuses_corrupt_member() -> None:
    data = bytearray(zip_of(("a", b"hello" * 1000)).getvalue())
    data[40:50] = b"\xff" * 10
    with pytest.raises(SbomError, match="w is not a valid zip"), open_archive(BytesIO(bytes(data)), "w") as archive:
        archive.read("a")


def test_read_member() -> None:
    with open_archive(zip_of(("a", b"12345")), "w") as archive:
        assert read_member(archive, "a", "w", limit=5) == b"12345"


def test_read_member_over_limit() -> None:
    with open_archive(zip_of(("a", b"12345")), "w") as archive, pytest.raises(SbomError, match="w: a is over the 4"):
        read_member(archive, "a", "w", limit=4)


def test_read_member_missing() -> None:
    with open_archive(zip_of(("a", b"")), "w") as archive, pytest.raises(SbomError, match="w has no b"):
        read_member(archive, "b", "w")


@pytest.mark.usefixtures("traced")
def test_read_member_refuses_understated_size() -> None:
    # the archive claims 10 bytes for 32 MiB; reading the member whole would decompress all of it before the CRC check
    data = bytearray(zip_of(("a", b"A" * 32 * 1024 * 1024)).getvalue())
    data[22:26] = data[(central := data.rfind(b"PK\x01\x02")) + 24 : central + 28] = struct.pack("<I", 10)
    tracemalloc.reset_peak()
    with pytest.raises(SbomError, match="Bad CRC-32 for file 'a'"), open_archive(BytesIO(bytes(data)), "w") as archive:
        read_member(archive, "a", "w")
    assert tracemalloc.get_traced_memory()[1] < 4 * 1024 * 1024


@pytest.fixture
def traced() -> Iterator[None]:
    tracemalloc.start()
    yield
    tracemalloc.stop()


def test_sha256_hex() -> None:
    assert sha256_hex(io.BytesIO(b"abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
