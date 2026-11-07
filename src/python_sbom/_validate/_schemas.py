from __future__ import annotations

import json
from collections import Counter
from importlib.resources import files
from typing import TYPE_CHECKING, Final

from jsonschema_rs import Draft7Validator, Registry
from license_expression import ExpressionError, ExpressionParseError, LicenseExpression
from spdx_tools.common.spdx_licensing import spdx_licensing
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser
from spdx_tools.spdx.validation.creation_info_validator import validate_creation_info
from spdx_tools.spdx.validation.extracted_licensing_info_validator import validate_extracted_licensing_infos
from spdx_tools.spdx.validation.package_validator import validate_package
from spdx_tools.spdx.validation.spdx_id_validators import validate_spdx_id

from ._limits import MAX_TEXT

if TYPE_CHECKING:
    from importlib.resources.abc import Traversable

    from jsonschema_rs import ValidationError
    from spdx_tools.spdx.model import Document, SpdxNoAssertion, SpdxNone

    from python_sbom._formats._spdx import Spdx

    from ._limits import Json


def schema_error(document: Json) -> str | None:
    detail: Final[ValidationError | None] = next(_VALIDATOR.iter_errors(document), None)
    if detail is None:
        return None
    steps: Final[str] = "".join(
        f"[{step}]" if isinstance(step, int) else f".{step}" if step.isidentifier() else f"[{step!r}]"
        for step in detail.instance_path
    )
    return f"{detail.message[:MAX_TEXT]} at {f'${steps}'[:MAX_TEXT]}"


def spdx_problems(spdx: Spdx) -> list[str]:
    try:
        parsed: Final[Document] = JsonLikeDictParser().parse(dict(spdx))
    except SPDXParsingError as error:
        return [f"SPDX rendering does not parse: {message}" for message in error.get_messages()]
    return [f"SPDX rendering invalid: {message}" for message in _invalid(parsed)]


def _invalid(document: Document) -> list[str]:
    # spdx-tools' validate_full_spdx_document looks every relationship end, and every package's own relationships, up
    # in lists, so its time grows with the square of the elements: 16,000 took a minute and a half. This runs its
    # validators of each element and does the lookups across elements in sets. The rendering writes no files, snippets
    # or annotations, and always the DESCRIBES relationship, so their checks are left out
    version: Final[str] = document.creation_info.spdx_version
    messages: Final[list[str]] = [
        message.validation_message for message in validate_creation_info(document.creation_info, version)
    ]
    license_refs: Final[frozenset[str | None]] = frozenset(
        info.license_id for info in document.extracted_licensing_info
    )
    for package in document.packages:
        messages.extend(validate_spdx_id(package.spdx_id, document))
        messages.extend(_license_problems(package.license_concluded, license_refs))
        messages.extend(_license_problems(package.license_declared, license_refs))
        messages.extend(message.validation_message for message in validate_package(package, version))
    ids: Final[Counter[str]] = Counter(package.spdx_id for package in document.packages)
    ids[document.creation_info.spdx_id] += 1
    for relationship in document.relationships:
        ends = (relationship.spdx_element_id, relationship.related_spdx_element_id)
        messages.extend(
            f'did not find the referenced spdx_id "{end}" in the SPDX document' for end in ends if end not in ids
        )
    messages.extend(
        message.validation_message for message in validate_extracted_licensing_infos(document.extracted_licensing_info)
    )
    if duplicates := sorted(spdx_id for spdx_id, count in ids.items() if count > 1):
        messages.append(
            f"every spdx_id must be unique within the document, but found the following duplicates: {duplicates}"
        )
    return messages


def _license_problems(
    expression: LicenseExpression | SpdxNoAssertion | SpdxNone | None, license_refs: frozenset[str | None]
) -> list[str]:
    # spdx-tools' validate_license_expression, with the LicenseRef ids it lists for every call gathered once
    if not isinstance(expression, LicenseExpression):
        return []
    problems: Final[list[str]] = [
        f"Unrecognized license reference: {symbol}. license_expression must only use IDs from the license list or"
        f" extracted licensing info, but is: {expression}"
        for symbol in spdx_licensing.validate(expression).invalid_symbols
        if symbol not in license_refs
    ]
    try:
        spdx_licensing.parse(str(expression), validate=True, strict=True)
    except ExpressionParseError as error:
        # an exception used as a license or the other way around; unknown symbols raise ExpressionError, listed above
        problems.append(f"{error}. for license_expression: {expression}")
    except ExpressionError:
        pass
    return problems


# the official CycloneDX schema files, unchanged: bom-1.6 and the jsf-0.82 it references from the specification's 1.6.2
# release, and the spdx license list from its 1.7.2 release, the newest, as the cyclonedx.org URL every schema version
# references serves the newest; Apache-2.0, see the LICENSE beside them. Format assertion is on, as in CycloneDX's own
# Draft 7 validation, and offline, so a reference missing from the registry fails instead of reaching the network
_SCHEMAS: Final[Traversable] = files(__package__) / "schemas"
_REFERENCED: Final[list[dict[str, Json]]] = [
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
