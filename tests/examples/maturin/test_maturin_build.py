from __future__ import annotations

import hashlib
import zipfile
from typing import TYPE_CHECKING, Final

import pytest

if TYPE_CHECKING:
    from conftest import Played, ReadSbom

pytestmark: Final[pytest.MarkDecorator] = pytest.mark.parametrize(
    "played", [("maturin", "session-maturin-build.console")], indirect=True, scope="module"
)


def test_documented_session(played: Played) -> None:
    assert played.output == played.expected


def test_sbom_names_the_wheel_it_sits_in(played: Played, read_sbom: ReadSbom) -> None:
    (wheel,) = (played.directory / "dist").glob("*.whl")
    references = read_sbom(wheel)["metadata"]["component"]["externalReferences"]
    assert [ref["url"].rsplit("/", 2)[1] for ref in references if ref["type"] == "attestation"] == [wheel.name]


def test_maturin_sbom_is_linked(played: Played, read_sbom: ReadSbom) -> None:
    (wheel,) = (played.directory / "dist").glob("*.whl")
    linked = zipfile.ZipFile(wheel).read("greet-1.0.dist-info/sboms/greet.cyclonedx.json")
    assert [
        (ref["url"], ref["hashes"])
        for ref in read_sbom(wheel)["metadata"]["component"]["externalReferences"]
        if ref["type"] == "bom"
    ] == [("greet.cyclonedx.json", [{"alg": "SHA-256", "content": hashlib.sha256(linked).hexdigest()}])]
