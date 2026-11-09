from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from python_sbom import BundledWheelInfo, ContentProvider, ProviderContext
from python_sbom._model._inputs import BundledWheel
from python_sbom._model._metadata import parse_metadata

if TYPE_CHECKING:
    from pathlib import PurePosixPath

    from conftest import Describe

    from python_sbom._model._inputs import Settings


def test_declared_dependency(describe: Describe) -> None:
    requirement = 'tomli>=2; python_version < "3.11"'
    document = describe(f"Requires-Dist: {requirement}\n")
    assert document["components"] == [
        {
            "type": "library",
            "bom-ref": f"requires-dist:{requirement}",
            "name": "tomli",
            "purl": "pkg:pypi/tomli",
            "externalReferences": [{"type": "distribution", "url": "https://pypi.org/project/tomli/"}],
            "properties": [
                {"name": "example:requires-dist", "value": requirement},
                {"name": "example:environment-marker", "value": 'python_version < "3.11"'},
            ],
        }
    ]


def test_repeated_requirement_is_one_component(describe: Describe) -> None:
    document = describe("Requires-Dist: packaging>=24\nRequires-Dist: packaging>=24\n")
    assert [component["bom-ref"] for component in document["components"]] == ["requires-dist:packaging>=24"]


def test_scope_names_bundled_directories(describe: Describe, settings: Settings) -> None:
    document = describe(settings=dataclasses.replace(settings, bundled_wheels=("src/b/*.whl", "src/a/x/*.whl")))
    assert document["metadata"]["properties"][0]["value"] == (
        "Components are the wheels bundled as data files under src/a/x and src/b and the direct runtime dependencies"
        " declared in the wheel's core metadata, which carry no version because the installer resolves them."
    )


def test_bundled_wheel_and_its_vendored_packages(describe: Describe) -> None:
    wheel = BundledWheel(
        path="src/pip-1.0-py3-none-any.whl",
        sha256="ab" * 32,
        metadata_name="pip-1.0.dist-info/METADATA",
        metadata=parse_metadata("Name: pip\nVersion: 1.0\n"),
        files=[],
        vendored=[("pip/_vendor/vendor.txt", parse_metadata("Name: urllib3\nVersion: 1.26.4\n"))],
    )

    class Seeded(ContentProvider):
        def __init__(self, name: str) -> None:
            self._name = name

        def bundled_wheel(self, context: ProviderContext, wheel: PurePosixPath) -> BundledWheelInfo:
            return BundledWheelInfo(
                properties=[{"name": f"{context.identity.property_prefix}:{self._name}", "value": str(wheel)}]
            )

    document = describe(bundled=[wheel], content=Seeded("seeded"))
    assert document["components"][0]["properties"][1] == {
        "name": "example:seeded",
        "value": "src/pip-1.0-py3-none-any.whl",
    }
    bundled_ref = "bundled:src/pip-1.0-py3-none-any.whl"
    assert document["dependencies"][:2] == [
        {"ref": "pkg:pypi/example@1.0", "dependsOn": [bundled_ref]},
        {"ref": bundled_ref, "dependsOn": [f"{bundled_ref}#vendored/pkg:pypi/urllib3@1.26.4"]},
    ]
