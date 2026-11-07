from __future__ import annotations

import csv
import hashlib
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # runs git to read the source revision
import uuid
import zipfile
from dataclasses import dataclass
from email.parser import Parser
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final, Protocol, TypeAlias
from urllib.parse import urlsplit

from hatchling.builders.utils import get_reproducible_timestamp
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from ._cyclonedx import (
    build_tools,
    component_from_metadata,
    contacts,
    document,
    external_reference,
    file_component,
    purl,
    timestamp,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import date, datetime, time
    from email.message import Message

    from ._cyclonedx import (
        Component,
        Contact,
        Dependency,
        Document,
        ExternalReference,
        License,
        OrganizationalEntity,
        Property,
    )

#: a value of a TOML table, as :mod:`tomllib` or hatchling hand it over
Toml: TypeAlias = "str | int | float | bool | datetime | date | time | list[Toml] | dict[str, Toml]"


class BundledWheelProperties(Protocol):
    """Extra properties for a wheel the project bundles as a data file."""

    def __call__(self, wheel: Path, /) -> list[Property]:
        """
        Describe one bundled wheel.

        :param wheel: the bundled wheel, an absolute path under the project root
        :returns: the properties to add after ``<project>:bundled-wheel``

        """


def _no_bundled_wheel_properties(_wheel: Path, /) -> list[Property]:
    return []


@dataclass(frozen=True, slots=True, kw_only=True)
class Project:
    """
    The source tree a wheel comes from, and what its SBOM should say about it.

    :param root: the project directory, where ``.git`` and the license files are
    :param supplier: the organization that supplies the project, or ``None`` to leave the supplier out
    :param repository: the repository URL, or ``None`` to take the first ``Source``, ``Repository`` or ``GitHub``
        project URL of the metadata
    :param default_branch: branch used in links to files in the repository
    :param bundled_wheels: glob patterns, relative to ``root``, of wheels the project ships as data files
    :param build_script: path, relative to ``root``, of a build script to list among the build tools, or ``None``
    :param bundled_wheel_properties: extra properties for each bundled wheel

    """

    root: Path
    supplier: OrganizationalEntity | None
    repository: str | None
    default_branch: str
    bundled_wheels: tuple[str, ...]
    build_script: PurePosixPath | None
    bundled_wheel_properties: BundledWheelProperties

    @classmethod
    def from_table(
        cls,
        table: Mapping[str, Toml],
        *,
        root: Path,
        where: str,
        build_script: PurePosixPath | None = None,
        bundled_wheel_properties: BundledWheelProperties = _no_bundled_wheel_properties,
    ) -> Project:
        """
        Read the settings from a configuration table, ignoring keys it does not know.

        :param table: the ``supplier``, ``repository``, ``default-branch`` and ``bundled-wheels`` settings
        :param root: the project directory
        :param where: where the table lives, for error messages, such as ``[tool.python-sbom]``
        :param build_script: path, relative to ``root``, of a build script to list among the build tools
        :param bundled_wheel_properties: extra properties for each bundled wheel
        :returns: the project
        :raises TypeError: when a setting has the wrong type

        """
        supplier = table.get("supplier")
        if supplier is not None and not (
            isinstance(supplier, dict)
            and supplier.keys() <= {"name", "url"}
            and isinstance(name := supplier.get("name"), str)
            and isinstance(urls := supplier.get("url", []), list)
            and all(isinstance(url, str) for url in urls)
        ):
            msg = f"`supplier` in {where} must be a table with a string `name` and an optional `url` string array"
            raise TypeError(msg)
        if not isinstance(repository := table.get("repository"), str | None):
            msg = f"`repository` in {where} must be a string"
            raise TypeError(msg)
        if not isinstance(default_branch := table.get("default-branch", "main"), str):
            msg = f"`default-branch` in {where} must be a string"
            raise TypeError(msg)
        if not (
            isinstance(patterns := table.get("bundled-wheels", []), list)
            and all(isinstance(pattern, str) for pattern in patterns)
        ):
            msg = f"`bundled-wheels` in {where} must be an array of strings"
            raise TypeError(msg)
        return cls(
            root=root,
            supplier=None if supplier is None else {"name": name, "url": [str(url) for url in urls]},
            repository=None if repository is None else repository.rstrip("/"),
            default_branch=default_branch,
            bundled_wheels=tuple(str(pattern) for pattern in patterns),
            build_script=build_script,
            bundled_wheel_properties=bundled_wheel_properties,
        )

    def describe(self, metadata: Message, wheel_name: str) -> Document:
        """
        Write the SBOM of a wheel.

        :param metadata: the wheel's ``METADATA``
        :param wheel_name: the wheel's file name, for its attestation link
        :returns: the CycloneDX 1.6 document

        """
        namespace = canonicalize_name(metadata["Name"])
        repository = self.repository or self._project_url_repository(metadata)
        root = self._root_component(metadata, wheel_name, repository)
        bundled = [self._bundled_component(wheel, namespace, repository) for wheel in self._bundled_wheel_paths()]
        declared = [_declared_dependency(requirement, namespace) for requirement in _runtime_requirements(metadata)]
        bundled_dependencies: Final[list[Dependency]] = [
            {"ref": component["bom-ref"], "dependsOn": references}
            for component in bundled
            if (references := [child["bom-ref"] for child in component["components"] if child["type"] == "library"])
        ]
        tools, tool_dependencies = build_tools()
        if self.build_script is not None:
            tools.insert(0, self._build_script_tool(self.build_script, metadata["Version"], repository))
        authors = _authors(metadata)
        licenses = _licenses(metadata)
        base = repository or f"https://pypi.org/project/{namespace}"
        return document(
            {
                "metadata": {
                    "timestamp": timestamp(),
                    "lifecycles": [{"phase": "build"}],
                    "tools": {"components": tools},
                    **({"manufacturer": self.supplier} if self.supplier else {}),
                    **({"authors": authors} if authors else {}),
                    **({"supplier": self.supplier} if self.supplier else {}),
                    "component": root,
                    **({"licenses": licenses} if licenses else {}),
                    "properties": [{"name": f"{namespace}:sbom:scope", "value": self._scope()}],
                },
                "components": [*bundled, *declared],
                "dependencies": [
                    {
                        "ref": root["bom-ref"],
                        "dependsOn": [component["bom-ref"] for component in [*bundled, *declared]],
                    },
                    *bundled_dependencies,
                    *tool_dependencies,
                ],
                # transitive runtime dependencies are unknown until install time
                "compositions": [{"aggregate": "incomplete", "dependencies": [root["bom-ref"]]}],
                "formulation": [
                    {
                        "bom-ref": "formula:wheel-build",
                        "workflows": [
                            {
                                "bom-ref": "workflow:wheel-build",
                                "uid": "wheel-build",
                                "name": "build the wheel and this SBOM",
                                "taskTypes": ["build"],
                                "resourceReferences": [{"ref": tool["bom-ref"]} for tool in tools],
                                "outputs": [{"type": "artifact", "resource": {"ref": root["bom-ref"]}}],
                                "inputs": [
                                    {
                                        "environmentVars": [
                                            {"name": "SOURCE_DATE_EPOCH", "value": str(get_reproducible_timestamp())}
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ],
            },
            uuid.uuid5(uuid.NAMESPACE_URL, f"{base}/sboms"),
        )

    @staticmethod
    def _project_url_repository(metadata: Message) -> str | None:
        return next(
            (
                url.strip().rstrip("/")
                for label, url in (entry.split(",", 1) for entry in metadata.get_all("Project-URL", []))
                if external_reference(label.strip(), url.strip())["type"] == "vcs"
            ),
            None,
        )

    def _root_component(self, metadata: Message, wheel_name: str, repository: str | None) -> Component:
        name, version = metadata["Name"], metadata["Version"]
        namespace = canonicalize_name(name)
        references: Final[list[ExternalReference]] = [
            external_reference(label.strip(), url.strip())
            for label, url in (entry.split(",", 1) for entry in metadata.get_all("Project-URL", []))
        ]
        references.extend([
            {"type": "distribution", "url": f"https://pypi.org/project/{name}/{version}/"},
            {"type": "attestation", "url": f"https://pypi.org/integrity/{name}/{version}/{wheel_name}/provenance"},
        ])
        if repository and urlsplit(repository).netloc == "github.com":
            references.extend([
                {"type": "security-contact", "url": f"{repository}/security/policy"},
                {"type": "advisories", "url": f"{repository}/security/advisories"},
            ])
        license_files: Final[list[str]] = metadata.get_all("License-File", [])
        if repository and license_files:
            references.append({"type": "license", "url": f"{repository}/blob/{self.default_branch}/{license_files[0]}"})
        properties: Final[list[Property]] = []
        if requires_python := metadata.get("Requires-Python"):
            properties.append({"name": f"{namespace}:requires-python", "value": requires_python})
        properties.extend({"name": "python:classifier", "value": value} for value in metadata.get_all("Classifier", []))
        properties.extend(
            {"name": "python:keyword", "value": keyword.strip()}
            for keyword in (metadata.get("Keywords") or "").split(",")
            if keyword.strip()
        )
        if commit := self._commit():
            if repository:
                references.append({
                    "type": "vcs",
                    "url": f"{repository}/tree/{commit}",
                    "comment": "exact source revision",
                })
            properties.append({"name": f"{namespace}:vcs-commit", "value": commit})
        authors = _authors(metadata)
        licenses = _licenses(metadata)
        copyright_line = self._copyright(license_files)
        package = purl(name, version)
        return {
            "type": "application",
            "bom-ref": package,
            **({"supplier": self.supplier} if self.supplier else {}),
            **({"authors": authors} if authors else {}),
            "name": name,
            "version": version,
            **({"description": summary} if (summary := metadata.get("Summary")) else {}),
            **({"licenses": licenses} if licenses else {}),
            **({"copyright": copyright_line} if copyright_line else {}),
            "purl": package,
            "externalReferences": references,
            "properties": properties,
        }

    def _commit(self) -> str | None:
        if not (self.root / ".git").exists() or (git := shutil.which("git")) is None:  # building from an sdist
            return None
        return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed arguments
            [git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True, cwd=self.root
        ).stdout.strip()

    def _copyright(self, license_files: list[str]) -> str | None:
        return next(
            (
                line
                for license_file in license_files
                if (path := self.root / license_file).is_file()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.startswith("Copyright")
            ),
            None,
        )

    def _bundled_component(self, wheel: Path, namespace: str, repository: str | None) -> Component:
        with zipfile.ZipFile(wheel) as archive:
            members: Final[list[str]] = sorted(archive.namelist())
            metadata_name: Final[str] = next(
                name for name in members if name.count("/") == 1 and name.endswith(".dist-info/METADATA")
            )
            metadata = Parser().parsestr(archive.read(metadata_name).decode("utf-8"))
            record = archive.read(metadata_name.replace("METADATA", "RECORD")).decode("utf-8")
            vendored: Final[list[tuple[str, Message]]] = [
                *_vendor_manifest(wheel, archive, members),
                *(
                    (name, Parser().parsestr(archive.read(name).decode("utf-8")))
                    for name in members
                    if "/_vendor/" in name and name.endswith(".dist-info/METADATA")
                ),
            ]
        component = component_from_metadata(metadata, "library")
        # a bundled wheel published from the same forge account as this project shares its supplier
        if (
            self.supplier
            and repository
            and any(reference["url"].startswith(_owner(repository)) for reference in component["externalReferences"])
        ):
            component["supplier"] = self.supplier
        sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
        component["hashes"] = [{"alg": "SHA-256", "content": sha256}]
        component["externalReferences"].append(
            {"type": "distribution", "url": f"https://pypi.org/project/{metadata['Name']}/{metadata['Version']}/"},
        )
        component["properties"] = [
            {"name": f"{namespace}:bundled-wheel", "value": wheel.relative_to(self.root).as_posix()},
            *self.bundled_wheel_properties(wheel),
            *component["properties"],
        ]
        component["evidence"] = {
            "identity": [
                {
                    "field": "purl",
                    "confidence": 1,
                    "methods": [{"technique": "manifest-analysis", "confidence": 1, "value": metadata_name}],
                },
                {
                    "field": "hash",
                    "confidence": 1,
                    "methods": [{"technique": "hash-comparison", "confidence": 1, "value": sha256}],
                },
            ],
        }
        component["components"] = [
            file_component(component["bom-ref"], path, digest, size)
            for path, digest, size in (row for row in csv.reader(StringIO(record, newline="")) if row)
            if digest
        ]
        children: Final[dict[str, Component]] = {}
        for source, child_metadata in vendored:
            child = component_from_metadata(child_metadata, "library")
            child["bom-ref"] = f"{component['bom-ref']}#vendored/{child['bom-ref']}"
            child["properties"].append({"name": f"{namespace}:vendored-manifest", "value": source})
            child["evidence"] = {
                "identity": [
                    {
                        "field": "purl",
                        "confidence": 1,
                        "methods": [{"technique": "manifest-analysis", "confidence": 1, "value": source}],
                    }
                ],
            }
            # a vendored .dist-info comes after the pip manifest line naming the same purl, so its metadata wins
            children[purl(child["name"], child["version"])] = child
        component["components"].extend(children[key] for key in sorted(children))
        return component

    def _bundled_wheel_paths(self) -> list[Path]:
        found = {path for pattern in self.bundled_wheels for path in self.root.glob(pattern)}
        return sorted(found, key=lambda path: path.relative_to(self.root).as_posix())

    def _build_script_tool(self, script: PurePosixPath, version: str, repository: str | None) -> Component:
        # a custom build hook shapes the document, so it is part of the toolchain a rebuild has to match
        tool: Final[Component] = {
            "type": "application",
            "bom-ref": f"tool:{script}",
            "name": script.name,
            "version": version,
            # str, so a Windows drive in an absolute path survives the join with the native root
            "hashes": [
                {"alg": "SHA-256", "content": hashlib.sha256((self.root / str(script)).read_bytes()).hexdigest()}
            ],
        }
        if repository:
            tool["externalReferences"] = [{"type": "vcs", "url": f"{repository}/blob/{self.default_branch}/{script}"}]
        return tool

    def _scope(self) -> str:
        if directories := sorted({str(PurePosixPath(pattern).parent) for pattern in self.bundled_wheels}):
            return (
                f"Components are the wheels bundled as data files under {' and '.join(directories)} and the direct"
                " runtime dependencies declared in the wheel's core metadata. The latter carry no version because"
                " they are resolved at install time, not at build time."
            )
        return (
            "Components are the direct runtime dependencies declared in the wheel's core metadata. They carry no"
            " version because they are resolved at install time, not at build time."
        )


def sbom_file_name(metadata: Message) -> str:
    return f"{canonicalize_name(metadata['Name'])}.cdx.json"


def _runtime_requirements(metadata: Message) -> list[str]:
    # an extra's requirements apply only when the extra is requested, so they are not runtime dependencies of the wheel
    return [
        requirement
        for requirement in metadata.get_all("Requires-Dist", [])
        if (marker := Requirement(requirement).marker) is None or "extra" not in str(marker)
    ]


def _declared_dependency(requirement: str, namespace: str) -> Component:
    parsed = Requirement(requirement)
    component: Final[Component] = {
        "type": "library",
        # the same distribution can be declared more than once with different markers, so the purl is not unique
        "bom-ref": f"requires-dist:{requirement}",
        "name": parsed.name,
        "purl": purl(parsed.name),
        "externalReferences": [{"type": "distribution", "url": f"https://pypi.org/project/{parsed.name}/"}],
        "properties": [{"name": f"{namespace}:requires-dist", "value": requirement}],
    }
    if parsed.marker is not None:
        component["properties"].append({"name": f"{namespace}:environment-marker", "value": str(parsed.marker)})
    return component


def _authors(metadata: Message) -> list[Contact]:
    # core metadata joins several names into one header
    if people := contacts(
        [name for entry in metadata.get_all("Maintainer", []) for name in entry.split(", ")],
        metadata.get_all("Maintainer-email", []),
    ):
        return people
    return contacts(
        [name for entry in metadata.get_all("Author", []) for name in entry.split(", ")],
        metadata.get_all("Author-email", []),
    )


def _licenses(metadata: Message) -> list[License]:
    if expression := metadata.get("License-Expression"):
        return [{"expression": expression, "acknowledgement": "declared"}]
    return []


def _vendor_manifest(wheel: Path, archive: zipfile.ZipFile, members: list[str]) -> list[tuple[str, Message]]:
    # pip lists what it vendors in _vendor/vendor.txt instead of shipping each vendored .dist-info
    found: Final[list[tuple[str, Message]]] = []
    for name in members:
        if not name.endswith("/_vendor/vendor.txt"):
            continue
        for line in archive.read(name).decode("utf-8").splitlines():
            if not (requirement := line.partition("#")[0].strip()):
                continue
            parsed = Requirement(requirement)
            pins = list(parsed.specifier)
            if len(pins) != 1 or pins[0].operator != "==" or "*" in pins[0].version:
                msg = f"Unpinned vendored dependency in {wheel.name}:{name}: {requirement}"
                raise ValueError(msg)
            found.append((name, Parser().parsestr(f"Name: {parsed.name}\nVersion: {pins[0].version}\n")))
    return found


def _owner(repository: str) -> str:
    parts = urlsplit(repository)
    return f"{parts.scheme}://{parts.netloc}/{parts.path.strip('/').split('/')[0]}/"


__all__ = [
    "BundledWheelProperties",
    "Project",
    "Toml",
    "sbom_file_name",
]
