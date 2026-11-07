from __future__ import annotations

from typing import Final

import pytest
from jsonschema_rs import Draft7Validator

from python_sbom._model._iri import iri_reference

_IRI_REFERENCE: Final[Draft7Validator] = Draft7Validator(
    {"type": "string", "format": "iri-reference"}, validate_formats=True
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param("https://example.org/a?b=1#c", "https://example.org/a?b=1#c", id="valid"),
        pytest.param("https://example.org/ü😀", "https://example.org/ü😀", id="unicode"),
        pytest.param("https://example.org/%e2%82", "https://example.org/%e2%82", id="percent-encoded"),
        pytest.param("UNKNOWN", "UNKNOWN", id="relative"),
        pytest.param("//example.org/a", "//example.org/a", id="network-path"),
        pytest.param("ssh://git@github.com/org/repo", "ssh://git@github.com/org/repo", id="userinfo"),
        pytest.param("http://[::1]:80/", "http://[::1]:80/", id="ipv6"),
        pytest.param("http://[v1.x]/", "http://[v1.x]/", id="ip-future"),
        pytest.param("https://example.org:/", "https://example.org:/", id="empty-port"),
        pytest.param("https://example.org/a b", "https://example.org/a%20b", id="space"),
        pytest.param("https://example.org/{a}", "https://example.org/%7Ba%7D", id="braces"),
        pytest.param('https://example.org/<a>|^`\\"', "https://example.org/%3Ca%3E%7C%5E%60%5C%22", id="delimiters"),
        pytest.param("https://example.org/a[1]?b[2]", "https://example.org/a%5B1%5D?b%5B2%5D", id="brackets"),
        pytest.param("https://example.org/a#b#c", "https://example.org/a#b%23c", id="second-hash"),
        pytest.param("https://example.org/%zz", "https://example.org/%25zz", id="bare-percent"),
        pytest.param("https://example.org/a\tb", "https://example.org/a%09b", id="control"),
        pytest.param("https://example.org/\x85\ue000", "https://example.org/%C2%85%EE%80%80", id="no-ucschar"),
        pytest.param("https://ex ample.org/", "https://ex%20ample.org/", id="host-space"),
        pytest.param("https://a@b@example.org/", "https://a%40b@example.org/", id="userinfo-at"),
        pytest.param("git@github.com:org/repo.git", None, id="scp-style"),
        pytest.param("https://example.org:port/", None, id="port"),
        pytest.param("https://example.org:\uff18\uff10/", None, id="non-ascii-port"),
        pytest.param("http://[bad/", None, id="unclosed-literal"),
        pytest.param("http://[fe80::1%eth0]/", None, id="zone-index"),
        pytest.param("http://[::1]x/", None, id="after-literal"),
    ],
)
def test_iri_reference(text: str, expected: str | None) -> None:
    assert iri_reference(text) == expected
    assert expected is None or _IRI_REFERENCE.is_valid(expected)
