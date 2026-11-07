from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Final, TypeAlias

from python_sbom._errors import MissingExtraError

try:  # ruff: ignore[too-many-statements-in-try-clause] # one guard names the extra every import here needs
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    from jsonschema.exceptions import ValidationError
    from jsonschema.validators import Draft7Validator, extend
    from spdx_tools.spdx.parser.error import SPDXParsingError
    from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
    from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
except ImportError as error:
    _MESSAGE: Final[str] = "validation needs the validate extra: pip install 'python-sbom[validate]'"
    raise MissingExtraError(_MESSAGE) from error

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from jsonschema.protocols import Validator

    from python_sbom._formats._spdx import Spdx

# a JSON value, as json.loads hands it over
_Json: TypeAlias = "str | int | float | bool | list[_Json] | dict[str, _Json] | None"
# a JSON value made hashable, keeping jsonschema's notion of equality
_Frozen: TypeAlias = "str | int | float | _Truth | tuple[_Frozen, ...] | frozenset[tuple[str, _Frozen]] | None"
_Keyword: TypeAlias = "Callable[[Validator, bool, _Json, dict[str, _Json]], Iterator[ValidationError]]"
# the message quotes the offending value, which for a document root runs to megabytes
_MAX_TEXT: Final[int] = 200


class _Truth(Enum):
    # jsonschema tells true and false apart from 1 and 0, which Python's equality does not
    TRUE = True
    FALSE = False


def schema_error(document: _Json) -> str | None:
    detail: Final[ValidationError | None] = next(iter(_VALIDATOR.iter_errors(document)), None)
    if detail is None:
        return None
    return f"{detail.message[:_MAX_TEXT]} at {detail.json_path[:_MAX_TEXT]}"


def spdx_problems(spdx: Spdx) -> list[str]:
    try:
        parsed: Final = JsonLikeDictParser().parse(dict(spdx))
    except SPDXParsingError as error:
        return [f"SPDX rendering does not parse: {message}" for message in error.get_messages()]
    return [f"SPDX rendering invalid: {message.validation_message}" for message in validate_full_spdx_document(parsed)]


def _unique_items(
    validator: Validator,
    unique: bool,  # ruff: ignore[boolean-type-hint-positional-argument] # jsonschema calls keywords positionally
    instance: _Json,
    schema: dict[str, _Json],
) -> Iterator[ValidationError]:
    # jsonschema compares every pair of items, ten seconds for five thousand components; two items freeze alike exactly
    # when its equal() holds for them, so one pass over the frozen items gives the same verdict
    if not unique or not isinstance(instance, list):
        return
    seen: Final[dict[_Frozen, int]] = {}
    for index, item in enumerate(instance):
        try:
            frozen = _freeze(item)
        except RecursionError:
            # freezing recurses once per level of an item, so a deeply nested one gets jsonschema's own check
            yield from _UNIQUE_ITEMS(validator, unique, instance, schema)
            return
        if (first := seen.setdefault(frozen, index)) != index:
            # jsonschema's message quotes the whole array, which the report clips before it names the problem
            yield ValidationError(f"item {index} repeats item {first}, yet the items must be unique")
            return


def _freeze(value: _Json) -> _Frozen:
    # a list freezes to a tuple and an object to a frozenset of its pairs, so the two never compare equal, as in
    # equal(); numbers keep Python's equality, where 1 equals 1.0 as it does there
    if isinstance(value, dict):
        return frozenset({(key, _freeze(item)) for key, item in value.items()})
    if isinstance(value, list):
        return tuple([_freeze(item) for item in value])
    if isinstance(value, bool):
        return _Truth(value)
    return value


# loading the schema takes about a second, so the validator is built once: the Draft 7 validator and format checks
# cyclonedx uses over its bundled schema and registry, with the uniqueItems check above swapped in; validating the
# parsed document skips the second parse validate_str does
_BASE: Final[Validator] = JsonStrictValidator(SchemaVersion.V1_6)._validator  # ruff: ignore[private-member-access] # no public accessor
_UNIQUE_ITEMS: Final[_Keyword] = Draft7Validator.VALIDATORS["uniqueItems"]
_VALIDATOR: Final[Validator] = extend(Draft7Validator, {"uniqueItems": _unique_items})(
    _BASE.schema,
    registry=_BASE._registry,  # ruff: ignore[private-member-access] # ty: ignore[unresolved-attribute] # see above
    format_checker=Draft7Validator.FORMAT_CHECKER,
)


__all__ = [
    "schema_error",
    "spdx_problems",
]
