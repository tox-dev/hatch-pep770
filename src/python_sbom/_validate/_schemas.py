from __future__ import annotations

from typing import TYPE_CHECKING, Final

from python_sbom._errors import MissingExtraError

try:
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    from spdx_tools.spdx.parser.error import SPDXParsingError
    from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
    from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
except ImportError as error:
    _MESSAGE: Final[str] = "validation needs the validate extra: pip install 'python-sbom[validate]'"
    raise MissingExtraError(_MESSAGE) from error

if TYPE_CHECKING:
    from python_sbom._formats._spdx import Spdx

# loading the schema takes about a second, so the validator is built once
_VALIDATOR: Final[JsonStrictValidator] = JsonStrictValidator(SchemaVersion.V1_6)


def schema_error(raw: str) -> str | None:
    try:
        error = _VALIDATOR.validate_str(raw, all_errors=False)
    except RecursionError:
        # the schema validator recurses once per nesting level, so a hostile document can exhaust the stack
        return "it nests too deeply to check"
    return None if error is None else str(error)


def spdx_problems(spdx: Spdx) -> list[str]:
    try:
        parsed = JsonLikeDictParser().parse(dict(spdx))
    except SPDXParsingError as error:
        return [f"SPDX rendering does not parse: {message}" for message in error.get_messages()]
    return [f"SPDX rendering invalid: {message.validation_message}" for message in validate_full_spdx_document(parsed)]


__all__ = [
    "schema_error",
    "spdx_problems",
]
