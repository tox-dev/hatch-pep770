from __future__ import annotations

import pytest
from packaging.metadata import Metadata

from python_sbom._model._components import component_from_metadata
from python_sbom._model._metadata import parse_metadata


def test_repeated_single_use_field_keeps_every_value() -> None:
    # packaging moves an Author given twice out of raw, and unparsed keeps both as written
    metadata = parse_metadata("Name: a\nVersion: 1\nAuthor: Ann\nAuthor: Bob\n")
    assert (metadata.values("author"), metadata.first("author")) == (["Ann", "Bob"], "Ann")


def test_absent_field() -> None:
    metadata = parse_metadata("Name: a\nVersion: 1\n")
    assert (metadata.values("classifiers"), metadata.first("summary")) == ([], None)


def test_without_name_and_version() -> None:
    metadata = parse_metadata("Summary: nameless\n")
    assert (metadata.name, metadata.version) == ("", "")


@pytest.mark.parametrize(
    ("fields", "keywords"),
    [
        pytest.param("Keywords: a,b\n", ["a,b"], id="comma-separated"),
        pytest.param("Keywords: a b\n", ["a b"], id="space-separated"),
        pytest.param("Keywords: a, b\n", ["a, b"], id="comma-and-space"),
        pytest.param("Keywords: a , b,c\n", ["a , b,c"], id="mixed-spacing"),
        pytest.param("Keywords: a\nKeywords: b\n", ["a", "b"], id="repeated"),
        pytest.param("", [], id="absent"),
    ],
)
def test_keywords(fields: str, keywords: list[str]) -> None:
    assert parse_metadata(f"Name: a\nVersion: 1\n{fields}").keywords() == keywords


@pytest.mark.parametrize(
    ("fields", "urls"),
    [
        pytest.param(
            "Project-URL: Source, https://a\nProject-URL: Docs, https://d\n",
            [("Source", "https://a"), ("Docs", "https://d")],
            id="distinct-labels",
        ),
        # packaging moves every Project-URL to unparsed when a label repeats, and none of them is lost
        pytest.param(
            "Project-URL: Source, https://a\nProject-URL: Source , https://b\nProject-URL: Docs, https://d\n",
            [("Source", "https://a"), ("Source", "https://b"), ("Docs", "https://d")],
            id="repeated-label",
        ),
        pytest.param("Project-URL: Source\nProject-URL: Docs, https://d\n", [("Docs", "https://d")], id="without-url"),
        pytest.param(
            "Project-URL: Source, https://a\nProject-URL: Source, https://b\nProject-URL: Bare\n",
            [("Source", "https://a"), ("Source", "https://b")],
            id="repeated-label-and-without-url",
        ),
    ],
)
def test_project_urls(fields: str, urls: list[tuple[str, str]]) -> None:
    assert parse_metadata(f"Name: a\nVersion: 1\n{fields}").project_urls() == urls


# the headers of installed distributions that packaging's validating parser rejects, which the SBOM still describes
@pytest.mark.parametrize(
    ("text", "described"),
    [
        pytest.param(
            "Metadata-Version: 2.1\nName: six\nVersion: 1.17.0\nLicense: MIT\n"
            "Classifier: License :: OSI Approved :: MIT License\nLicense-File: LICENSE\n",
            ("six", "1.17.0", ["MIT License", "MIT"]),
            id="six-license-file-before-2.4",
        ),
        pytest.param(
            "Metadata-Version: 2.1\nName: covdefaults\nVersion: 2.3.0\nLicense: MIT\n"
            "Description-Content-Type: text/markdown\nLicense-File: LICENSE\nRequires-Dist: coverage (>=6.0.2)\n",
            ("covdefaults", "2.3.0", ["MIT"]),
            id="covdefaults-license-file-before-2.4",
        ),
        pytest.param(
            "Metadata-Version: 2.0\nName: ply\nVersion: 3.11\nLicense: BSD\nDescription-Content-Type: UNKNOWN\n"
            "Platform: UNKNOWN\n",
            ("ply", "3.11", ["BSD"]),
            id="ply-unknown-version-and-content-type",
        ),
        pytest.param(
            "Metadata-Version: 2.1\nName: uri-template\nVersion: 1.3.0\nLicense: MIT License\n"
            "Project-URL: homepage, https://gitlab.linss.com/open-source/python/uri-template\nKeywords: config\n"
            "License-File: LICENSE\nProvides-Extra: dev\nRequires-Dist: mypy ; extra == 'dev'\n",
            ("uri-template", "1.3.0", ["MIT License"]),
            id="uri-template-license-file-before-2.4",
        ),
    ],
)
def test_metadata_the_validating_parser_rejects(text: str, described: tuple[str, str, list[str]]) -> None:
    with pytest.raises(ExceptionGroup):
        Metadata.from_email(text, validate=True)
    component = component_from_metadata(parse_metadata(text))
    names = [entry["license"]["name"] for entry in component["licenses"] if "name" in entry["license"]]
    assert (component["name"], component["version"], names) == described


@pytest.mark.parametrize("newline", [pytest.param("\n", id="lf"), pytest.param("\r\n", id="crlf")])
def test_body_is_not_read(newline: str) -> None:
    # the headers end at the first empty line; a line of whitespace still continues the one before
    text = newline.join(["Name: a", "Version: 1", "Summary: one", "  more", "", "Author: in the body", ""])
    metadata = parse_metadata(text)
    assert (metadata.first("summary"), metadata.first("author"), "description" in metadata.raw) == (
        f"one{newline}  more",
        None,
        False,
    )
