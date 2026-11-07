from __future__ import annotations

import json
from importlib.resources import files
from typing import TYPE_CHECKING, Final, TypeAlias

from python_sbom._errors import MissingExtraError

try:
    from jsonschema_rs import Draft7Validator, Registry
    from spdx_tools.spdx.parser.error import SPDXParsingError
    from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
    from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
except ImportError as error:
    _MESSAGE: Final[str] = "validation needs the validate extra: pip install 'python-sbom[validate]'"
    raise MissingExtraError(_MESSAGE) from error

if TYPE_CHECKING:
    from importlib.resources.abc import Traversable

    from jsonschema_rs import ValidationError

    from python_sbom._formats._spdx import Spdx

# a JSON value, as json.loads hands it over
_Json: TypeAlias = "str | int | float | bool | list[_Json] | dict[str, _Json] | None"
# the message quotes the offending value, which for a document root runs to megabytes
_MAX_TEXT: Final[int] = 200


def schema_error(document: _Json) -> str | None:
    detail: Final[ValidationError | None] = next(_VALIDATOR.iter_errors(document), None)
    if detail is None:
        return None
    steps: Final[str] = "".join(
        f"[{step}]" if isinstance(step, int) else f".{step}" if step.isidentifier() else f"[{step!r}]"
        for step in detail.instance_path
    )
    return f"{detail.message[:_MAX_TEXT]} at {f'${steps}'[:_MAX_TEXT]}"


def spdx_problems(spdx: Spdx) -> list[str]:
    try:
        parsed: Final = JsonLikeDictParser().parse(dict(spdx))
    except SPDXParsingError as error:
        return [f"SPDX rendering does not parse: {message}" for message in error.get_messages()]
    return [f"SPDX rendering invalid: {message.validation_message}" for message in validate_full_spdx_document(parsed)]


# the official CycloneDX schema files, unchanged: bom-1.6 and the jsf-0.82 it references from the specification's 1.6.2
# release, and the spdx license list from its 1.7.2 release, the newest, as the cyclonedx.org URL every schema version
# references serves the newest; Apache-2.0, see the LICENSE beside them. Format assertion is on, as in CycloneDX's own
# Draft 7 validation, and offline, so a reference missing from the registry fails instead of reaching the network
_SCHEMAS: Final[Traversable] = files(__package__) / "schemas"
_REFERENCED: Final[list[dict[str, _Json]]] = [
    json.loads((_SCHEMAS / name).read_text(encoding="utf-8")) for name in ("spdx.schema.json", "jsf-0.82.schema.json")
]
_VALIDATOR: Final[Draft7Validator] = Draft7Validator(
    json.loads((_SCHEMAS / "bom-1.6.schema.json").read_text(encoding="utf-8")),
    validate_formats=True,
    offline=True,
    registry=Registry([(str(schema["$id"]), schema) for schema in _REFERENCED]),
)

__all__ = [
    "schema_error",
    "spdx_problems",
]
