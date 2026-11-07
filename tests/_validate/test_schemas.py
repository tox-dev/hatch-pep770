from __future__ import annotations

import sys
from typing import TypeAlias

import pytest
from jsonschema.validators import Draft7Validator

from python_sbom._errors import MissingExtraError
from python_sbom._validate._document import validate_document
from python_sbom._validate._schemas import _unique_items, schema_error

# a JSON value, as json.loads hands it over
_Json: TypeAlias = "str | int | float | bool | list[_Json] | dict[str, _Json] | None"


def test_validate_without_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    # None in sys.modules makes the import fail, as when the extra is not installed
    monkeypatch.setitem(sys.modules, "cyclonedx.schema", None)
    monkeypatch.delitem(sys.modules, "python_sbom._validate._schemas", raising=False)
    with pytest.raises(MissingExtraError, match=r"pip install 'python-sbom\[validate\]'"):
        validate_document("{}", None)


def test_schema_error_names_the_path() -> None:
    document: _Json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "one"}
    assert schema_error(document) == "'one' is not of type 'integer' at $.version"


def test_schema_error_clips_the_offending_value() -> None:
    document: _Json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "x" * 1000}
    assert schema_error(document) == f"'{'x' * 199} at $.version"


@pytest.mark.parametrize(
    "items",
    [
        pytest.param([1, 1.0], id="int-equals-float"),
        pytest.param([True, 1], id="true-is-not-one"),
        pytest.param([False, 0], id="false-is-not-zero"),
        pytest.param([True, True], id="repeated-boolean"),
        pytest.param(["1", 1], id="string-is-not-number"),
        pytest.param([None, None], id="repeated-null"),
        pytest.param([[1, 2], [2, 1]], id="list-order-counts"),
        pytest.param([[1], {"0": 1}], id="list-is-not-object"),
        pytest.param([{"a": 1, "b": [True]}, {"b": [True], "a": 1.0}], id="object-key-order-does-not-count"),
        pytest.param([{"a": True}, {"a": 1}], id="nested-boolean"),
        pytest.param([], id="empty"),
    ],
)
def test_unique_items_matches_jsonschema(items: list[_Json]) -> None:
    validator = Draft7Validator({})
    expected = bool(list(Draft7Validator.VALIDATORS["uniqueItems"](validator, True, items, {})))
    assert bool(list(_unique_items(validator, True, items, {}))) is expected


@pytest.mark.parametrize(
    ("unique", "instance"), [pytest.param(False, [1, 1], id="not-asked"), pytest.param(True, "11", id="not-an-array")]
)
def test_unique_items_skips(unique: bool, instance: _Json) -> None:
    assert list(_unique_items(Draft7Validator({}), unique, instance, {})) == []


def test_unique_items_too_deep_to_freeze() -> None:
    # freezing the item overflows the stack, so jsonschema's own check judges the array, and a lone item is unique
    nested: list[_Json] = []
    for _ in range(sys.getrecursionlimit()):
        nested = [nested]
    assert list(_unique_items(Draft7Validator({}), True, [nested], {})) == []


def test_duplicate_components_are_rejected() -> None:
    components: list[_Json] = [{"type": "library", "name": f"part-{index}"} for index in range(2_000)]
    components.append({"type": "library", "name": "part-0"})
    document: _Json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}
    assert schema_error(document) == "item 2000 repeats item 0, yet the items must be unique at $.components"


def test_many_unique_components_pass() -> None:
    components: list[_Json] = [
        {"type": "library", "bom-ref": f"ref-{index}", "name": f"part-{index}"} for index in range(20_000)
    ]
    assert schema_error({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}) is None
