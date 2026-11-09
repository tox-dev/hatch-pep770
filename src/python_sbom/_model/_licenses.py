"""Turn core metadata's license fields into CycloneDX licenses."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression

if TYPE_CHECKING:
    from ._metadata import CoreMetadata
    from ._types import License


def licenses(metadata: CoreMetadata) -> list[License]:
    # a License-Expression is taken as declared; otherwise each License field and License classifier name is declared,
    # and the SPDX ids they map to are added as concluded
    if expression := metadata.first("license_expression"):
        try:
            return [{"expression": canonicalize_license_expression(expression), "acknowledgement": "declared"}]
        except InvalidLicenseExpression:
            # an expression SPDX rejects, such as "MIT WITH GPL-3.0-only", stays as the name the metadata gives
            return [{"license": {"name": expression, "acknowledgement": "declared"}}]
    names = [entry.rsplit(" :: ", 1)[-1] for entry in metadata.values("classifiers") if entry.startswith("License :: ")]
    if (declared := metadata.first("license")) and "\n" not in declared:
        names.append(declared)
    found: Final[list[License]] = [{"license": {"name": name, "acknowledgement": "declared"}} for name in names]
    # a license policy judges SPDX ids only, so the names stay bare when any one of them does not resolve, and the
    # policy reports that instead of judging a partial set
    identifiers = [identifier for name in names if (identifier := _spdx_license(name)) is not None]
    if len(identifiers) == len(names):
        found.extend(
            {"license": {"id": identifier, "acknowledgement": "concluded"}} for identifier in dict.fromkeys(identifiers)
        )
    return found


def _spdx_license(name: str) -> str | None:
    # only the license classifiers that name exactly one SPDX license; "BSD License" or "Apache Software License" leave
    # the version or variant open
    if identifier := {
        "ISC License (ISCL)": "ISC",
        "MIT License": "MIT",
        "MIT No Attribution License (MIT-0)": "MIT-0",
        "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
        "Python Software Foundation License": "PSF-2.0",
        "The Unlicense (Unlicense)": "Unlicense",
    }.get(name):
        return identifier
    try:
        canonical = canonicalize_license_expression(name)
    except InvalidLicenseExpression:
        return None
    # a CycloneDX license id holds one entry of the SPDX license list, never an expression or a LicenseRef
    return canonical if re.fullmatch(r"[A-Za-z0-9.-]+", canonical) and not canonical.startswith("LicenseRef-") else None


__all__ = [
    "licenses",
]
