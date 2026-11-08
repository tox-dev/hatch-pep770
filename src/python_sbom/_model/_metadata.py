from __future__ import annotations

import re
from dataclasses import dataclass
from email.parser import HeaderParser
from email.policy import compat32
from typing import TYPE_CHECKING, Final, Literal, TypeAlias

from packaging.metadata import parse_email

if TYPE_CHECKING:
    from packaging.metadata import RawMetadata

# the fields python-sbom reads, by their key in packaging's RawMetadata
Field: TypeAlias = Literal[
    "author",
    "author_email",
    "classifiers",
    "home_page",
    "license",
    "license_expression",
    "license_files",
    "maintainer",
    "maintainer_email",
    "name",
    "provides_extra",
    "requires_dist",
    "requires_python",
    "summary",
    "version",
]

# the empty line that ends the headers, as the email parser ends them; a line of whitespace continues a header
_BODY: Final[re.Pattern[str]] = re.compile(r"^\r?\n", re.MULTILINE)
# unparsed keys a field by its header name, lowercased, which is the RawMetadata key with dashes except for these
_HEADERS: Final[dict[str, str]] = {"classifiers": "classifier", "license_files": "license-file"}


def parse_metadata(text: str) -> CoreMetadata:
    # not validated: the SBOM describes a distribution whose metadata breaks the specification as well, as written; the
    # body holds the long description, which nothing reads, and parsing it took most of the time
    headers: Final = text[: match.start()] if (match := _BODY.search(text)) else text
    raw, unparsed = parse_email(headers)
    return CoreMetadata(raw=raw, unparsed=unparsed, headers=headers)


@dataclass(frozen=True, slots=True, kw_only=True)
class CoreMetadata:
    raw: RawMetadata
    unparsed: dict[str, list[str]]
    # the header block as written, for the values packaging reshapes
    headers: str = ""

    @property
    def name(self) -> str:
        return self.first("name") or ""

    def first(self, field: Field) -> str | None:
        return next(iter(self.values(field)), None)

    def values(self, field: Field) -> list[str]:
        # packaging keeps a field it cannot take as declared, such as a single-use field given twice, out of raw and its
        # values as written in unparsed, from where they are still described
        match self.raw.get(field):
            case str() as value:
                return [value]
            case list() as values:
                return values
        return self.unparsed.get(_HEADERS.get(field, field.replace("_", "-")), [])

    @property
    def version(self) -> str:
        return self.first("version") or ""

    def keywords(self) -> list[str]:
        # packaging splits Keywords at commas and strips each keyword, so the header is read again, as the distribution
        # wrote it, only when one is there; packaging parses the block with the same policy
        if "keywords" in self.raw:
            return HeaderParser(policy=compat32).parsestr(self.headers).get_all("keywords", [])
        return self.unparsed.get("keywords", [])

    def project_urls(self) -> list[tuple[str, str]]:
        # a label given twice sends every Project-URL to unparsed, where each splits at its first comma as packaging
        # splits them; an entry without a URL names nothing to reference
        pairs: Final[list[tuple[str, str]]] = (
            list(self.raw["project_urls"].items())
            if "project_urls" in self.raw
            else [
                (label.strip(), url.strip())
                for label, _, url in (entry.partition(",") for entry in self.unparsed.get("project-url", []))
            ]
        )
        return [(label, url) for label, url in pairs if url]


__all__ = [
    "CoreMetadata",
    "Field",
    "parse_metadata",
]
