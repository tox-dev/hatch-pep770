from __future__ import annotations

import json
from typing import TYPE_CHECKING, Final

import pytest

from python_sbom._validate._licenses import license_problems

if TYPE_CHECKING:
    from python_sbom import Component, License

_ALLOWED: Final[frozenset[str]] = frozenset({"MIT", "BSD-3-Clause", "GPL-2.0-only"})


@pytest.mark.parametrize(
    "licenses",
    [
        pytest.param([{"expression": "MIT"}], id="expression"),
        pytest.param([{"license": {"id": "mit", "acknowledgement": "concluded"}}], id="id-case-insensitive"),
        pytest.param([{"expression": "MIT OR GPL-3.0-only"}], id="any-of"),
        pytest.param([{"expression": "(GPL-3.0-only OR MIT) AND BSD-3-Clause"}], id="grouped"),
        pytest.param([{"expression": "GPL-2.0-only WITH Classpath-exception-2.0"}], id="exception"),
    ],
)
def test_allows(licenses: list[License]) -> None:
    assert license_problems([shipped(licenses)], _ALLOWED) == []


def shipped(licenses: list[License]) -> Component:
    return {
        "type": "library",
        "bom-ref": "bundled:lib.whl",
        "name": "lib",
        "hashes": [{"alg": "SHA-256", "content": "ab" * 32}],
        "licenses": licenses,
    }


@pytest.mark.parametrize(
    ("licenses", "problem"),
    [
        pytest.param(
            [{"expression": "MIT AND GPL-3.0-only"}],
            "license MIT AND GPL-3.0-only is outside the allowed licenses ['BSD-3-Clause', 'GPL-2.0-only', 'MIT']",
            id="denied",
        ),
        pytest.param(
            [{"license": {"name": "BSD License", "acknowledgement": "declared"}}],
            "declares license names ['BSD License'] with no SPDX id",
            id="names",
        ),
        pytest.param([], "declares no license", id="none"),
        pytest.param([{"expression": "MIT AND"}], "license expression 'MIT AND' is malformed: it ends early", id="end"),
        pytest.param([{"expression": "(MIT"}], "license expression '(MIT' is malformed: it ends early", id="open"),
        pytest.param(
            [{"expression": "(MIT ISC)"}],
            "license expression '(MIT ISC)' is malformed: expected ')', got 'ISC'",
            id="pair",
        ),
        pytest.param([{"expression": "MIT)"}], "license expression 'MIT)' is malformed: unexpected ')'", id="close"),
        pytest.param(
            [{"expression": "AND MIT"}], "license expression 'AND MIT' is malformed: unexpected 'AND'", id="op"
        ),
        pytest.param(
            [{"expression": "MIT WITH OR"}], "license expression 'MIT WITH OR' is malformed: unexpected 'OR'", id="with"
        ),
    ],
)
def test_reports(licenses: list[License], problem: str) -> None:
    assert license_problems([shipped(licenses)], _ALLOWED) == [f"bundled:lib.whl: {problem}"]


def test_deep_nesting_is_malformed() -> None:
    # each level costs the parser stack frames, so this deep a nesting would exhaust the stack
    expression = f"{'(' * 5000}MIT{')' * 5000}"
    assert license_problems([shipped([{"expression": expression}])], _ALLOWED) == [
        (
            f"bundled:lib.whl: license expression {expression!r} is malformed: it nests 5000 levels deep, over the 32"
            " level limit"
        )
    ]


def test_nesting_up_to_the_limit_parses() -> None:
    expression = f"{'(' * 32}MIT{')' * 32}"
    assert license_problems([shipped([{"expression": expression}])], _ALLOWED) == []


def test_judges_only_shipped_components() -> None:
    declared: Component = {"type": "library", "bom-ref": "requires-dist:click", "name": "click"}
    vendored: Component = {"type": "library", "bom-ref": "bundled:outer.whl#vendored", "name": "vendored"}
    outer = shipped([{"expression": "MIT"}])
    outer["components"] = [vendored, {"type": "file", "bom-ref": "outer#a.py", "name": "a.py"}]
    assert license_problems([declared, outer], frozenset({"MIT"})) == []


def test_component_without_bom_ref_is_named() -> None:
    # the schema makes the bom-ref optional, so the loaded JSON, not the typed document, loses it
    component = json.loads(json.dumps(shipped([])))
    del component["bom-ref"]
    assert license_problems([component], _ALLOWED) == ["lib: declares no license"]
