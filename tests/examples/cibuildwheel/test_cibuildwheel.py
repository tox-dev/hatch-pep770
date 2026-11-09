from __future__ import annotations

import hashlib
import subprocess
import sys
import zipfile
from typing import TYPE_CHECKING, Final

import pytest

if TYPE_CHECKING:
    from conftest import Played, ReadSbom

pytestmark: Final[pytest.MarkDecorator] = pytest.mark.parametrize(
    "played", [("auditwheel", "session.console")], indirect=True, scope="module"
)


def test_documented_session(played: Played) -> None:
    assert played.output == played.expected


def test_sbom_names_the_wheel_it_sits_in(played: Played, read_sbom: ReadSbom) -> None:
    (wheel,) = (played.directory / "wheelhouse").glob("*.whl")
    references = read_sbom(wheel)["metadata"]["component"]["externalReferences"]
    assert [ref["url"].rsplit("/", 2)[1] for ref in references if ref["type"] == "attestation"] == [wheel.name]


def test_auditwheel_sbom_is_linked(played: Played, read_sbom: ReadSbom) -> None:
    (wheel,) = (played.directory / "wheelhouse").glob("*.whl")
    linked = zipfile.ZipFile(wheel).read("greet-1.0.dist-info/sboms/auditwheel.cdx.json")
    assert [
        (ref["url"], ref["hashes"])
        for ref in read_sbom(wheel)["metadata"]["component"]["externalReferences"]
        if ref["type"] == "bom"
    ] == [("auditwheel.cdx.json", [{"alg": "SHA-256", "content": hashlib.sha256(linked).hexdigest()}])]


def test_auditwheel_sbom_repeats_a_bom_ref(played: Played) -> None:
    # auditwheel lists the wheel both as the document's subject and among its components, under one bom-ref
    (wheel,) = (played.directory / "wheelhouse").glob("*.whl")
    result = subprocess.run(
        [sys.executable, "-m", "python_sbom", "validate", str(wheel)], capture_output=True, text=True, check=False
    )
    problem = f"auditwheel.cdx.json: bom-ref values repeat: pkg:pypi/greet@1.0?file_name={wheel.name}"
    assert (result.returncode, result.stderr) == (
        1,
        f"SBOM invalid: {wheel.name}: greet-1.0.dist-info/sboms/{problem}\n",
    )
