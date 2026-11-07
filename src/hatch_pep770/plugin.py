"""The hatchling build hook that writes a PEP 770 CycloneDX SBOM into the wheel."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from email.parser import Parser
from functools import cached_property
from io import StringIO
from itertools import starmap
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlsplit

from hatchling.__about__ import __version__ as hatchling_version
from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from hatchling.builders.utils import get_reproducible_timestamp
from hatchling.builders.wheel import WheelBuilder
from hatchling.utils.constants import DEFAULT_BUILD_SCRIPT
from packaging.requirements import Requirement

from .cyclonedx import (
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
    from email.message import Message

    from hatchling.metadata.core import CoreMetadata
    from packaging.specifiers import Specifier

    from .cyclonedx import (
        Body,
        Component,
        Contact,
        Dependency,
        Document,
        ExternalReference,
        License,
        OrganizationalEntity,
        Property,
        Workflow,
    )


class Pep770BuildHook(BuildHookInterface):
    """
    Write a PEP 770 CycloneDX 1.6 SBOM into the wheel's ``.dist-info/sboms/`` directory.

    The document describes the project from its core metadata, the runtime dependencies it declares, any wheels it
    bundles as data files, and the build toolchain. It holds nothing about the build machine and takes its timestamp
    from ``SOURCE_DATE_EPOCH``, so a rebuild with the same source, toolchain and epoch produces the same bytes on any
    operating system.

    Subclass it in a hatchling custom build hook to add project-specific detail; see :meth:`bundled_wheel_properties`.

    """

    PLUGIN_NAME = "pep770"
    _sbom_directory: Path | None = None

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:  # ruff: ignore[unused-method-argument]
        # `version` is hatchling's build variant name (e.g. "standard"), not the package version
        if not isinstance(builder := self.build_config.builder, WheelBuilder):
            return
        if "sbom_files" not in build_data:  # pragma: <3.10 cover # hatchling 1.28, the first with it, needs 3.10
            self.app.display_warning(
                f"hatchling {hatchling_version} cannot embed SBOMs (1.28 adds it), so none written"
            )
            return
        tag = build_data.get("tag") or (
            builder.get_best_matching_tag() if build_data["infer_tag"] else builder.get_default_tag()
        )
        content = json.dumps(self._document(f"{builder.artifact_project_id}-{tag}.whl"), indent=2)
        # written outside self.directory, which hatchling also uses as the wheel's output directory, so no stray copy
        # lands next to the built artifacts
        self._sbom_directory = Path(tempfile.mkdtemp(prefix="hatch-pep770-"))
        # bytes, so the line endings do not depend on the build machine's OS
        (out := self._sbom_directory / f"{self._namespace}.cdx.json").write_bytes(f"{content}\n".encode())
        build_data["sbom_files"].append(str(out))

    def finalize(self, version: str, build_data: dict[str, Any], artifact_path: str) -> None:  # ruff: ignore[unused-method-argument]
        if self._sbom_directory is not None:
            shutil.rmtree(self._sbom_directory)
            self._sbom_directory = None

    def bundled_wheel_properties(self, wheel: Path) -> list[Property]:  # ruff: ignore[unused-method-argument, no-self-use]
        """
        Return extra properties for one wheel the project bundles as a data file.

        The default adds none. A subclass overrides it to say what the project does with the wheel, for example which
        Python versions receive it. The properties follow ``<project>:bundled-wheel`` and precede the ones taken from
        the wheel's metadata.

        :param wheel: the bundled wheel, an absolute path under the project root
        :returns: the properties to add

        """
        return []

    @property
    def _namespace(self) -> str:
        # hatchling normalizes the name; it also prefixes the CycloneDX property names this hook writes
        return self.metadata.core.name

    def _document(self, wheel_name: str) -> Document:
        core: Final[CoreMetadata] = self.metadata.core
        version: Final[str] = self.metadata.version
        root = self._root_component(core, version, wheel_name)
        bundled = [self._bundled_component(wheel) for wheel in self._bundled_wheels]
        declared = [self._declared_dependency(requirement) for requirement in core.dependencies]
        tools, tool_dependencies = build_tools()
        if script := self._build_script_tool(version):
            tools.insert(0, script)
        bundled_dependencies: Final[list[Dependency]] = [
            {"ref": component["bom-ref"], "dependsOn": references}
            for component in bundled
            if (references := [child["bom-ref"] for child in component["components"] if child["type"] == "library"])
        ]
        supplier = self._supplier
        body: Final[Body] = {
            "metadata": {
                "timestamp": timestamp(),
                "lifecycles": [{"phase": "build"}],
                "tools": {"components": tools},
                **({"manufacturer": supplier} if supplier else {}),
                **({"authors": self._authors} if self._authors else {}),
                **({"supplier": supplier} if supplier else {}),
                "component": root,
                **({"licenses": self._licenses} if self._licenses else {}),
                "properties": [{"name": f"{self._namespace}:sbom:scope", "value": self._scope}],
            },
            "components": [*bundled, *declared],
            "dependencies": [
                {"ref": root["bom-ref"], "dependsOn": [component["bom-ref"] for component in [*bundled, *declared]]},
                *bundled_dependencies,
                *tool_dependencies,
            ],
            # transitive runtime dependencies are unknown until install time
            "compositions": [{"aggregate": "incomplete", "dependencies": [root["bom-ref"]]}],
            "formulation": [{"bom-ref": "formula:wheel-build", "workflows": [self._workflow(root, tools)]}],
        }
        base: Final[str] = self._repository or f"https://pypi.org/project/{self._namespace}"
        return document(body, uuid.uuid5(uuid.NAMESPACE_URL, f"{base}/sboms"))

    def _root_component(self, core: CoreMetadata, version: str, wheel_name: str) -> Component:
        package = purl(core.name, version)
        references: Final[list[ExternalReference]] = list(starmap(external_reference, core.urls.items()))
        references.extend([
            {"type": "distribution", "url": f"https://pypi.org/project/{core.name}/{version}/"},
            {"type": "attestation", "url": f"https://pypi.org/integrity/{core.name}/{version}/{wheel_name}/provenance"},
        ])
        if (repository := self._repository) and urlsplit(repository).netloc == "github.com":
            references.extend([
                {"type": "security-contact", "url": f"{repository}/security/policy"},
                {"type": "advisories", "url": f"{repository}/security/advisories"},
            ])
        if repository and core.license_files:
            references.append({"type": "license", "url": f"{repository}/blob/{self._branch}/{core.license_files[0]}"})
        properties: Final[list[Property]] = []
        if core.requires_python:
            properties.append({"name": f"{self._namespace}:requires-python", "value": core.requires_python})
        properties.extend({"name": "python:classifier", "value": classifier} for classifier in core.classifiers)
        properties.extend({"name": "python:keyword", "value": keyword} for keyword in core.keywords)
        if commit := self._commit():
            if repository:
                references.append({
                    "type": "vcs",
                    "url": f"{repository}/tree/{commit}",
                    "comment": "exact source revision",
                })
            properties.append({"name": f"{self._namespace}:vcs-commit", "value": commit})
        supplier = self._supplier
        copyright_line = self._copyright(core.license_files)
        return {
            "type": "application",
            "bom-ref": package,
            **({"supplier": supplier} if supplier else {}),
            **({"authors": self._authors} if self._authors else {}),
            "name": core.name,
            "version": version,
            **({"description": core.description} if core.description else {}),
            **({"licenses": self._licenses} if self._licenses else {}),
            **({"copyright": copyright_line} if copyright_line else {}),
            "purl": package,
            "externalReferences": references,
            "properties": properties,
        }

    @cached_property
    def _supplier(self) -> OrganizationalEntity | None:
        if (supplier := self.config.get("supplier")) is None:
            return None
        if not (
            isinstance(supplier, dict)
            and isinstance(name := supplier.get("name"), str)
            and isinstance(urls := supplier.get("url", []), list)
            and all(isinstance(url, str) for url in urls)
            and supplier.keys() <= {"name", "url"}
        ):
            msg = f"{self._option('supplier')} must be a table with a string `name` and an optional `url` string array"
            raise TypeError(msg)
        return {"name": name, "url": urls}

    def _option(self, name: str) -> str:
        return f"Option `{name}` of build hook `{self.PLUGIN_NAME}`"

    @cached_property
    def _authors(self) -> list[Contact]:
        maintainers = self.metadata.core.maintainers_data
        authors = self.metadata.core.authors_data
        people = maintainers if maintainers["name"] or maintainers["email"] else authors
        return contacts(people["name"], people["email"])

    @cached_property
    def _licenses(self) -> list[License]:
        if expression := self.metadata.core.license_expression:
            return [{"expression": expression, "acknowledgement": "declared"}]
        return []

    @cached_property
    def _repository(self) -> str | None:
        if (repository := self.config.get("repository")) is not None:
            if not isinstance(repository, str):
                msg = f"{self._option('repository')} must be a string"
                raise TypeError(msg)
            return repository.rstrip("/")
        return next(
            (
                url.rstrip("/")
                for label, url in self.metadata.core.urls.items()
                if external_reference(label, url)["type"] == "vcs"
            ),
            None,
        )

    @cached_property
    def _branch(self) -> str:
        if not isinstance(branch := self.config.get("default-branch", "main"), str):
            msg = f"{self._option('default-branch')} must be a string"
            raise TypeError(msg)
        return branch

    def _commit(self) -> str | None:
        if not (Path(self.root) / ".git").exists() or (git := shutil.which("git")) is None:  # building from an sdist
            return None
        try:
            result = subprocess.run(
                [git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True, cwd=self.root
            )
        except subprocess.CalledProcessError as error:
            self.app.display_warning(f"git rev-parse HEAD failed, so the SBOM names no source revision: {error.stderr}")
            return None
        return result.stdout.strip()

    def _copyright(self, license_files: list[str]) -> str | None:
        for license_file in license_files:
            for line in (Path(self.root) / license_file).read_text(encoding="utf-8").splitlines():
                if line.startswith("Copyright"):
                    return line
        return None

    @cached_property
    def _bundled_wheels(self) -> list[Path]:
        root = Path(self.root)
        found = {path for pattern in self._bundled_patterns for path in root.glob(pattern)}
        return sorted(found, key=lambda path: path.relative_to(root).as_posix())

    @cached_property
    def _bundled_patterns(self) -> list[str]:
        patterns = self.config.get("bundled-wheels", [])
        if not (isinstance(patterns, list) and all(isinstance(pattern, str) for pattern in patterns)):
            msg = f"{self._option('bundled-wheels')} must be an array of strings"
            raise TypeError(msg)
        return patterns

    def _bundled_component(self, wheel: Path) -> Component:
        with zipfile.ZipFile(wheel) as archive:
            members: Final[list[str]] = sorted(archive.namelist())
            metadata_name: Final[str] = next(
                name for name in members if name.count("/") == 1 and name.endswith(".dist-info/METADATA")
            )
            metadata = Parser().parsestr(archive.read(metadata_name).decode("utf-8"))
            record = archive.read(metadata_name.replace("METADATA", "RECORD")).decode("utf-8")
            vendored_metadata: Final[list[tuple[str, Message]]] = [
                *self._vendor_manifest(wheel, archive, members),
                *(
                    (name, Parser().parsestr(archive.read(name).decode("utf-8")))
                    for name in members
                    if "/_vendor/" in name and name.endswith(".dist-info/METADATA")
                ),
            ]
        component = component_from_metadata(metadata, "library")
        if (
            (supplier := self._supplier)
            and (owner := self._repository_owner)
            and any(reference["url"].startswith(owner) for reference in component["externalReferences"])
        ):
            component["supplier"] = supplier
        sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
        component["hashes"] = [{"alg": "SHA-256", "content": sha256}]
        component["externalReferences"].append(
            {"type": "distribution", "url": f"https://pypi.org/project/{metadata['Name']}/{metadata['Version']}/"},
        )
        component["properties"] = [
            {"name": f"{self._namespace}:bundled-wheel", "value": wheel.relative_to(self.root).as_posix()},
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
        vendored_components: Final[dict[str, Component]] = {}
        for source, vendored in vendored_metadata:
            child: Final[Component] = component_from_metadata(vendored, "library")
            child["bom-ref"] = f"{component['bom-ref']}#vendored/{child['purl']}"
            child["properties"].append({"name": f"{self._namespace}:vendored-manifest", "value": source})
            child["evidence"] = {
                "identity": [
                    {
                        "field": "purl",
                        "confidence": 1,
                        "methods": [{"technique": "manifest-analysis", "confidence": 1, "value": source}],
                    }
                ],
            }
            # a distribution's own .dist-info wins over the pip-style manifest line naming the same purl
            vendored_components[child["purl"]] = child
        component["components"].extend(vendored_components[key] for key in sorted(vendored_components))
        return component

    @staticmethod
    def _vendor_manifest(wheel: Path, archive: zipfile.ZipFile, members: list[str]) -> list[tuple[str, Message]]:
        # pip lists what it vendors in _vendor/vendor.txt instead of shipping each vendored .dist-info
        found: Final[list[tuple[str, Message]]] = []
        for name in members:
            if not name.endswith("/_vendor/vendor.txt"):
                continue
            for line in archive.read(name).decode("utf-8").splitlines():
                if not (requirement := line.partition("#")[0].strip()):
                    continue
                parsed: Final[Requirement] = Requirement(requirement)
                pins: Final[list[Specifier]] = list(parsed.specifier)
                if len(pins) != 1 or pins[0].operator != "==" or "*" in pins[0].version:
                    msg: Final[str] = f"Unpinned vendored dependency in {wheel.name}:{name}: {requirement}"
                    raise ValueError(msg)
                found.append((name, Parser().parsestr(f"Name: {parsed.name}\nVersion: {pins[0].version}\n")))
        return found

    @cached_property
    def _repository_owner(self) -> str | None:
        # a bundled wheel published from the same forge account as this project shares its supplier
        if (repository := self._repository) is None:
            return None
        parts = urlsplit(repository)
        return f"{parts.scheme}://{parts.netloc}/{parts.path.strip('/').split('/')[0]}/"

    def _declared_dependency(self, requirement: str) -> Component:
        parsed = Requirement(requirement)
        component: Final[Component] = {
            "type": "library",
            # the same distribution can be declared more than once with different markers, so the purl is not unique
            "bom-ref": f"requires-dist:{requirement}",
            "name": parsed.name,
            "purl": purl(parsed.name),
            "externalReferences": [{"type": "distribution", "url": f"https://pypi.org/project/{parsed.name}/"}],
            "properties": [{"name": f"{self._namespace}:requires-dist", "value": requirement}],
        }
        if parsed.marker is not None:
            component["properties"].append({
                "name": f"{self._namespace}:environment-marker",
                "value": str(parsed.marker),
            })
        return component

    def _build_script_tool(self, version: str) -> Component | None:
        # a custom build hook script shapes the document, so it is part of the toolchain a rebuild has to match
        if self.PLUGIN_NAME != "custom":
            return None
        script = PurePosixPath(self.config.get("path", DEFAULT_BUILD_SCRIPT))
        tool: Final[Component] = {
            "type": "application",
            "bom-ref": f"tool:{script}",
            "name": script.name,
            "version": version,
            "hashes": [
                {"alg": "SHA-256", "content": hashlib.sha256((Path(self.root) / script).read_bytes()).hexdigest()}
            ],
        }
        if repository := self._repository:
            tool["externalReferences"] = [{"type": "vcs", "url": f"{repository}/blob/{self._branch}/{script}"}]
        return tool

    @staticmethod
    def _workflow(root: Component, tools: list[Component]) -> Workflow:
        return {
            "bom-ref": "workflow:wheel-build",
            "uid": "wheel-build",
            "name": "build the wheel and this SBOM",
            "taskTypes": ["build"],
            "resourceReferences": [{"ref": tool["bom-ref"]} for tool in tools],
            "outputs": [{"type": "artifact", "resource": {"ref": root["bom-ref"]}}],
            "inputs": [
                {"environmentVars": [{"name": "SOURCE_DATE_EPOCH", "value": str(get_reproducible_timestamp())}]},
            ],
        }

    @cached_property
    def _scope(self) -> str:
        declared = (
            "the direct runtime dependencies declared in the wheel's core metadata. The latter carry no version"
            " because they are resolved at install time, not at build time."
        )
        if directories := sorted({str(PurePosixPath(pattern).parent) for pattern in self._bundled_patterns}):
            return f"Components are the wheels bundled as data files under {' and '.join(directories)} and {declared}"
        return (
            "Components are the direct runtime dependencies declared in the wheel's core metadata. They carry no"
            " version because they are resolved at install time, not at build time."
        )


__all__ = [
    "Pep770BuildHook",
]
