from __future__ import annotations

import hashlib
import sys
from importlib.resources import files
from typing import TYPE_CHECKING

import pytest
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

from python_sbom._errors import MissingExtraError
from python_sbom._formats._spdx import render_spdx
from python_sbom._validate._document import validate_document
from python_sbom._validate._schemas import schema_error, spdx_problems

if TYPE_CHECKING:
    from collections.abc import Callable

    from conftest import Describe

    from python_sbom import Component
    from python_sbom._formats._spdx import Spdx
    from python_sbom._validate._document import Json


@pytest.mark.parametrize(
    ("path", "release", "digest"),
    [
        pytest.param(
            "schema/bom-1.6.schema.json",
            "1.6.2",
            "18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d",
            id="bom-1.6",
        ),
        pytest.param(
            "schema/jsf-0.82.schema.json",
            "1.6.2",
            "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
            id="jsf-0.82",
        ),
        pytest.param(
            "schema/spdx.schema.json",
            "1.7.2",
            "4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359",
            id="spdx",
        ),
        pytest.param(
            "LICENSE", "1.7.2", "6c29f22a4a7385285c6f579ec9f33c5e989f00739d6b257243a0b082ec9447ae", id="license"
        ),
    ],
)
def test_schema_files_are_the_upstream_release(path: str, release: str, digest: str) -> None:
    # the SHA-256 of https://raw.githubusercontent.com/CycloneDX/specification/<release>/<path>, so the shipped copy
    # stays the released file byte for byte; a newer release replaces the file and its digest together
    shipped = files("python_sbom._validate") / "schemas" / path.rpartition("/")[2]
    assert hashlib.sha256(shipped.read_bytes()).hexdigest() == digest, f"not the file of the {release} release"


@pytest.mark.parametrize(
    "module",
    [
        pytest.param("jsonschema_rs", id="jsonschema-rs"),
        pytest.param("license_expression", id="license-expression"),
        pytest.param("spdx_tools", id="spdx-tools"),
    ],
)
def test_validate_without_extra(monkeypatch: pytest.MonkeyPatch, module: str) -> None:
    # None in sys.modules makes the import fail, as when the extra is not installed; even a document the cheap checks
    # would reject reports the missing extra
    monkeypatch.setitem(sys.modules, module, None)
    with pytest.raises(MissingExtraError, match=r"pip install 'python-sbom\[validate\]'"):
        validate_document(b"not JSON", None)


def test_validate_with_broken_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    # find_spec finds the extra's modules, yet one of their dependencies, such as spdx-tools' beartype, fails to import
    monkeypatch.setitem(sys.modules, "python_sbom._validate._schemas", None)
    with pytest.raises(MissingExtraError, match=r"pip install 'python-sbom\[validate\]'") as raised:
        validate_document(b'{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}', None)
    assert isinstance(raised.value.__cause__, ImportError)


def test_schema_error_names_the_path() -> None:
    document: Json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "one"}
    assert schema_error(document) == '"one" is not of type "integer" at $.version'


def test_schema_error_quotes_keys_that_are_not_names() -> None:
    document: Json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"bom-ref": ""}}}
    assert schema_error(document) == '"type" is a required property at $.metadata.component'
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "library", "name": "a", "bom-ref": ""}},
    }
    assert schema_error(document) == "\"\" is shorter than 1 character at $.metadata.component['bom-ref']"


def test_schema_error_clips_the_offending_value() -> None:
    document: Json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "x" * 1000}
    assert schema_error(document) == f'"{"x" * 199} at $.version'


def _url(value: str) -> dict[str, Json]:
    return {"externalReferences": [{"type": "website", "url": value}]}


@pytest.mark.parametrize(
    ("fields", "valid"),
    [
        pytest.param(_url("https://example.org/a?b=c#d"), True, id="url"),
        pytest.param(_url("https://exämple.org/ü"), True, id="url-non-ascii"),
        # RFC 3987 section 2.2: ucschar runs to U+1FFFD, past the Basic Multilingual Plane
        pytest.param(_url("https://example.org/😀"), True, id="url-astral"),
        # RFC 3986 section 3.2.2: IP-literal = "[" ( IPv6address / IPvFuture ) "]"
        pytest.param(_url("http://[::1]/"), True, id="url-ipv6-literal"),
        pytest.param(_url("https://example.org/\n"), False, id="url-trailing-newline"),
        pytest.param(_url("https://exa mple.org"), False, id="url-space"),
        pytest.param(_url("https://example.org/%zz"), False, id="url-bad-percent-escape"),
        # RFC 3339 section 5.6: time-second runs to 60 for a leap second
        pytest.param({"metadata": {"timestamp": "2016-12-31T23:59:60Z"}}, True, id="timestamp-leap-second"),
        pytest.param({"metadata": {"timestamp": "2016-12-31T23:59:59Z\n"}}, False, id="timestamp-trailing-newline"),
        # RFC 6531 Mailbox: a local part and a domain, the domain's labels starting with a letter or digit
        pytest.param({"metadata": {"authors": [{"email": "a@b.org"}]}}, True, id="email"),
        pytest.param({"metadata": {"authors": [{"email": "@b.org"}]}}, False, id="email-without-local-part"),
        pytest.param({"metadata": {"authors": [{"email": "a@-b.org"}]}}, False, id="email-label-starts-with-hyphen"),
        # draft 7 section 6.3.3: patterns are ECMA-262, whose $ does not match before a final newline
        pytest.param({"serialNumber": "urn:uuid:bde8d34d-2da7-5045-bd69-644208002436\n"}, False, id="pattern-newline"),
    ],
)
def test_formats_follow_their_rfcs(fields: dict[str, Json], valid: bool) -> None:
    assert (schema_error({"bomFormat": "CycloneDX", "specVersion": "1.6", **fields}) is None) is valid


@pytest.mark.parametrize(
    ("first", "second", "unique"),
    [
        pytest.param({"version": 1}, {"version": 1.0}, False, id="int-equals-float"),
        pytest.param({"version": "1"}, {"version": "1"}, False, id="same"),
        pytest.param({"version": "1", "group": "g"}, {"group": "g", "version": "1"}, False, id="key-order"),
        pytest.param({"version": "1"}, {"version": "2"}, True, id="different"),
    ],
)
def test_unique_items(first: dict[str, Json], second: dict[str, Json], unique: bool) -> None:
    components: list[Json] = [{"type": "library", "name": "a", **first}, {"type": "library", "name": "a", **second}]
    assert (schema_error({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}) is None) is unique


def test_many_unique_components_pass() -> None:
    components: list[Json] = [
        {"type": "library", "bom-ref": f"r{index}", "name": f"n{index}"} for index in range(20_000)
    ]
    assert schema_error({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}) is None


def _declare(spdx: Spdx, expression: str, text: str | None = None) -> None:
    spdx["packages"][0]["licenseDeclared"] = expression
    if text is not None:
        spdx["hasExtractedLicensingInfos"] = [
            {"licenseId": "LicenseRef-Custom", "extractedText": text, "name": "custom"}
        ]


@pytest.mark.parametrize(
    ("mutate", "valid"),
    [
        pytest.param(lambda _: None, True, id="as-rendered"),
        pytest.param(
            lambda spdx: spdx.update(documentNamespace="https://example.org/a#fragment"), False, id="namespace"
        ),
        pytest.param(
            lambda spdx: spdx["relationships"].append({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-ghost",
            }),
            False,
            id="unknown-relationship-end",
        ),
        pytest.param(lambda spdx: spdx["packages"].append(spdx["packages"][0]), False, id="duplicate-id"),
        pytest.param(
            lambda spdx: spdx["packages"][0].update(checksums=[{"algorithm": "SHA256", "checksumValue": "ab"}]),
            False,
            id="short-checksum",
        ),
        pytest.param(lambda spdx: _declare(spdx, "MIT AND Foo-Bar"), False, id="unknown-license"),
        pytest.param(lambda spdx: _declare(spdx, "GPL-2.0-only WITH MIT"), False, id="license-as-exception"),
        pytest.param(lambda spdx: _declare(spdx, "MIT OR LicenseRef-Custom", "custom"), True, id="license-ref"),
        pytest.param(lambda spdx: _declare(spdx, "MIT OR LicenseRef-Custom", ""), False, id="license-ref-without-text"),
    ],
)
def test_spdx_problems_match_spdx_tools(describe: Describe, mutate: Callable[[Spdx], None], valid: bool) -> None:
    # the full validation of spdx-tools, whose time grows with the square of the elements, is the reference
    spdx = render_spdx(describe("Requires-Dist: click\n"))
    mutate(spdx)
    reference = validate_full_spdx_document(JsonLikeDictParser().parse(dict(spdx)))
    assert spdx_problems(spdx) == [f"SPDX rendering invalid: {message.validation_message}" for message in reference]
    assert (not reference) is valid


def test_many_packages_pass(describe: Describe) -> None:
    # spdx-tools' full validation took a minute and a half for 16,000 packages, so this guards the linear checks
    document = describe()
    libraries: list[Component] = [
        {"type": "library", "bom-ref": f"r{index}", "name": f"n{index}"} for index in range(20_000)
    ]
    document["components"].extend(libraries)
    document["dependencies"][0].setdefault("dependsOn", []).extend(f"r{index}" for index in range(20_000))
    assert spdx_problems(render_spdx(document)) == []
