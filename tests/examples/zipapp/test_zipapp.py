from __future__ import annotations

import zipfile
from typing import TYPE_CHECKING, Final

import pytest

if TYPE_CHECKING:
    from conftest import Played, ReadSbom

pytestmark: Final[pytest.MarkDecorator] = pytest.mark.parametrize(
    "played", [("zipapp", "session.console")], indirect=True, scope="module"
)


def test_documented_session(played: Played) -> None:
    assert played.output == played.expected


def test_wheel_in_the_archive_names_itself(played: Played, read_sbom: ReadSbom) -> None:
    (wheel,) = (played.directory / "dist").glob("*.whl")
    references = read_sbom(wheel)["metadata"]["component"]["externalReferences"]
    assert [ref["url"].rsplit("/", 2)[1] for ref in references if ref["type"] == "attestation"] == [wheel.name]


def test_archive_carries_its_sbom_at_the_top(played: Played) -> None:
    assert "greet.pyz.cdx.json" in zipfile.ZipFile(played.directory / "greet.pyz").namelist()
