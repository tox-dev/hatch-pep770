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
        pytest.param(
            [{"expression": "MIT AND"}],
            "license expression 'MIT AND' is malformed: AND requires two or more licenses as in: MIT AND BSD",
            id="end",
        ),
        pytest.param([{"expression": "(MIT"}], "license expression '(MIT' is malformed: Invalid expression", id="open"),
        pytest.param(
            [{"expression": "(MIT ISC)"}],
            "license expression '(MIT ISC)' is malformed: Invalid symbols sequence such as (A B) for token: \"ISC\" at"
            " position: 5",
            id="pair",
        ),
        pytest.param(
            [{"expression": "MIT)"}],
            "license expression 'MIT)' is malformed: Unbalanced parenthesis for token: \")\" at position: 3",
            id="close",
        ),
        pytest.param(
            [{"expression": "AND MIT"}],
            "license expression 'AND MIT' is malformed: Invalid operator sequence without symbols such as AND OR or OR"
            ' OR for token: "AND"',
            id="op",
        ),
        pytest.param(
            [{"expression": "MIT WITH OR"}],
            "license expression 'MIT WITH OR' is malformed: Invalid expression for token: \"WITH\" at position: 4",
            id="with",
        ),
        pytest.param([{"expression": " "}], "license expression ' ' is malformed: it is empty", id="empty"),
        pytest.param(
            [{"expression": "( OR MIT"}],
            "license expression '( OR MIT' is malformed: it does not parse",
            id="assertion",
        ),
        pytest.param([{"expression": "()"}], "license expression '()' is malformed: it does not parse", id="no-group"),
    ],
)
def test_reports(licenses: list[License], problem: str) -> None:
    assert license_problems([shipped(licenses)], _ALLOWED) == [f"bundled:lib.whl: {problem}"]


@pytest.mark.parametrize(
    "expression",
    [
        pytest.param(f"{'(' * 5000}MIT{')' * 5000}", id="parentheses"),
        pytest.param(
            f"{''.join(f'MIT {operator} (' for operator in ('AND', 'OR') * 2500)}MIT{')' * 5000}", id="operators"
        ),
    ],
)
def test_deep_nesting_is_allowed(expression: str) -> None:
    # a recursive walk would exhaust the stack this deep
    assert license_problems([shipped([{"expression": expression}])], _ALLOWED) == []


def test_deep_nesting_is_denied() -> None:
    expression = f"{'MIT AND (' * 5000}GPL-3.0-only{')' * 5000}"
    assert license_problems([shipped([{"expression": expression}])], _ALLOWED) == [
        f"bundled:lib.whl: license {expression} is outside the allowed licenses ['BSD-3-Clause', 'GPL-2.0-only', 'MIT']"
    ]


@pytest.mark.parametrize(
    ("expression", "allowed", "problems"),
    [
        pytest.param(
            "LicenseRef-Apache",
            frozenset({"Apache-2.0"}),
            ["bundled:lib.whl: license LicenseRef-Apache is outside the allowed licenses ['Apache-2.0']"],
            id="license-ref-is-not-apache",
        ),
        pytest.param("Net-SNMP", frozenset({"Net-SNMP"}), [], id="spdx-id-is-kept"),
    ],
)
def test_judges_the_declared_id_not_an_alias(expression: str, allowed: frozenset[str], problems: list[str]) -> None:
    assert license_problems([shipped([{"expression": expression}])], allowed) == problems


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
