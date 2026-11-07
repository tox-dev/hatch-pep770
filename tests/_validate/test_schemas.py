from __future__ import annotations

import hashlib
import sys
from importlib.resources import files
from typing import TypeAlias

import pytest

from python_sbom._errors import MissingExtraError
from python_sbom._validate._document import validate_document
from python_sbom._validate._schemas import schema_error

# a JSON value, as json.loads hands it over
_Json: TypeAlias = "str | int | float | bool | list[_Json] | dict[str, _Json] | None"


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


def test_validate_without_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    # None in sys.modules makes the import fail, as when the extra is not installed
    monkeypatch.setitem(sys.modules, "jsonschema_rs", None)
    monkeypatch.delitem(sys.modules, "python_sbom._validate._schemas", raising=False)
    with pytest.raises(MissingExtraError, match=r"pip install 'python-sbom\[validate\]'"):
        validate_document("{}", None)


def test_schema_error_names_the_path() -> None:
    document: _Json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "one"}
    assert schema_error(document) == '"one" is not of type "integer" at $.version'


def test_schema_error_quotes_keys_that_are_not_names() -> None:
    document: _Json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"bom-ref": ""}}}
    assert schema_error(document) == '"type" is a required property at $.metadata.component'
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "library", "name": "a", "bom-ref": ""}},
    }
    assert schema_error(document) == "\"\" is shorter than 1 character at $.metadata.component['bom-ref']"


def test_schema_error_clips_the_offending_value() -> None:
    document: _Json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "x" * 1000}
    assert schema_error(document) == f'"{"x" * 199} at $.version'


def _url(value: str) -> dict[str, _Json]:
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
def test_formats_follow_their_rfcs(fields: dict[str, _Json], valid: bool) -> None:
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
def test_unique_items(first: dict[str, _Json], second: dict[str, _Json], unique: bool) -> None:
    components: list[_Json] = [{"type": "library", "name": "a", **first}, {"type": "library", "name": "a", **second}]
    assert (schema_error({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}) is None) is unique


def test_many_unique_components_pass() -> None:
    components: list[_Json] = [
        {"type": "library", "bom-ref": f"r{index}", "name": f"n{index}"} for index in range(20_000)
    ]
    assert schema_error({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}) is None
