from __future__ import annotations

from typing import TYPE_CHECKING, Final

from python_sbom._errors import MissingExtraError

try:
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator, JsonValidationError
    from spdx_tools.spdx.parser.error import SPDXParsingError
    from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
    from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
except ImportError as error:
    _MESSAGE: Final[str] = "validation needs the validate extra: pip install 'python-sbom[validate]'"
    raise MissingExtraError(_MESSAGE) from error

if TYPE_CHECKING:
    from jsonschema.exceptions import ValidationError

    from python_sbom._formats._spdx import Spdx

# loading the schema takes about a second, so the validator is built once
_VALIDATOR: Final[JsonStrictValidator] = JsonStrictValidator(SchemaVersion.V1_6)
# the message quotes the offending value, which for a document root runs to megabytes
_MAX_TEXT: Final[int] = 200


def schema_error(raw: str) -> str | None:
    error: Final = _VALIDATOR.validate_str(raw, all_errors=False)
    # all_errors=False returns one error or None, but under a runtime check type checkers do not follow
    if not isinstance(error, JsonValidationError):
        return None
    detail: Final[ValidationError] = error.data
    return f"{detail.message[:_MAX_TEXT]} at {detail.json_path[:_MAX_TEXT]}"


def spdx_problems(spdx: Spdx) -> list[str]:
    try:
        parsed: Final = JsonLikeDictParser().parse(dict(spdx))
    except SPDXParsingError as error:
        return [f"SPDX rendering does not parse: {message}" for message in error.get_messages()]
    return [f"SPDX rendering invalid: {message.validation_message}" for message in validate_full_spdx_document(parsed)]


__all__ = [
    "schema_error",
    "spdx_problems",
]
