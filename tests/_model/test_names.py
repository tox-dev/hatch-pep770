from __future__ import annotations

import pytest

from python_sbom._model._names import purl, pypi_url, reference_type, sbom_file_name


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        pytest.param("Bug Tracker", "issue-tracker", id="spaced"),
        pytest.param("Release-Notes", "release-notes", id="dashed"),
        pytest.param("Source_Code", "vcs", id="underscored"),
        pytest.param("Funding", "other", id="unknown"),
    ],
)
def test_reference_type_normalizes_labels(label: str, expected: str) -> None:
    assert reference_type(label) == expected


def test_purl_normalizes_every_spelling_alike() -> None:
    assert {purl(name, "1.0") for name in ("jaraco.context", "jaraco_context", "Jaraco-Context")} == {
        "pkg:pypi/jaraco-context@1.0"
    }


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        pytest.param("1.0", "https://pypi.org/project/pip/1.0/", id="release"),
        pytest.param(None, "https://pypi.org/project/pip/", id="project"),
    ],
)
def test_pypi_url(version: str | None, expected: str) -> None:
    assert pypi_url("pip", version) == expected


def test_sbom_file_name_uses_the_normalized_name() -> None:
    assert sbom_file_name("My_Project") == "my-project.cdx.json"
