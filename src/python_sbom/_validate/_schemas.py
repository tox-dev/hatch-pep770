from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

if TYPE_CHECKING:
    from python_sbom._formats._spdx import Spdx


def schema_error(raw: str) -> str | None:
    error = _validator().validate_str(raw, all_errors=False)
    return None if error is None else str(error)


@cache  # building the validator loads the whole schema, which takes a second
def _validator() -> JsonStrictValidator:
    return JsonStrictValidator(SchemaVersion.V1_6)


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
