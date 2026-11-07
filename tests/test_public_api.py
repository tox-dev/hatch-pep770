from __future__ import annotations

import collections.abc
import email.message
import importlib
import importlib.metadata
import inspect
import pathlib
import pkgutil
import typing
from typing import Final

import pytest

import python_sbom
import python_sbom.hatch

_PUBLIC: Final[set[str]] = {
    "BundledWheelInfo",
    "Component",
    "Contact",
    "ContentProvider",
    "Contributions",
    "Dependency",
    "Evidence",
    "ExternalReference",
    "Hash",
    "Identity",
    "IdentityMethod",
    "License",
    "LicenseInfo",
    "OrganizationalEntity",
    "ProjectIdentity",
    "Property",
    "ProviderContext",
    "SbomError",
    "Settings",
    "__version__",
}


def test_public_api() -> None:
    assert set(python_sbom.__all__) == _PUBLIC


def test_hatch_api() -> None:
    assert set(python_sbom.hatch.__all__) == {"SbomBuildHook"}


def reached(start: object) -> set[object]:  # simplint: ignore[SMP602] # hints are arbitrary typing objects
    # every python_sbom type a hint of a public name leads to, through fields, parameters and nested hints
    found: set[object] = set()  # simplint: ignore[SMP602] # see above
    pending: list[object] = [start]  # simplint: ignore[SMP602] # see above
    while pending:
        if (item := pending.pop()) in found:
            continue
        found.add(item)
        if typing.is_typeddict(item) or inspect.isclass(item):
            pending.extend(typing.get_type_hints(item, globalns=_names(), include_extras=True).values())
            for _, member in inspect.getmembers(item, inspect.isfunction):
                if member.__module__.startswith("python_sbom"):
                    pending.extend(typing.get_type_hints(member, globalns=_names(), include_extras=True).values())
        pending.extend(typing.get_args(item))
        if (origin := typing.get_origin(item)) is not None:
            pending.append(origin)
    return {item for item in found if getattr(item, "__module__", "").startswith("python_sbom")}


@pytest.mark.parametrize("name", sorted(_PUBLIC - {"__version__"}), ids=str)
def test_public_types_only_reach_public_types(name: str) -> None:
    assert reached(getattr(python_sbom, name)) - exported() == set()


def test_hook_only_reaches_public_types() -> None:
    assert reached(python_sbom.hatch.SbomBuildHook) - exported() == set()


def exported() -> set[object]:  # simplint: ignore[SMP602] # see above
    return {getattr(python_sbom, name) for name in _PUBLIC} | {python_sbom.hatch.SbomBuildHook}


def _names() -> dict[str, object]:  # simplint: ignore[SMP602] # see above
    # the annotations name types the modules import only for type checking, so every module's names resolve them
    modules = [
        pathlib,
        collections.abc,
        typing,
        *(importlib.import_module(found.name) for found in pkgutil.walk_packages(python_sbom.__path__, "python_sbom.")),
    ]
    names = dict(member for module in modules for member in inspect.getmembers(module))
    return {**names, "Message": email.message.Message, "PackageMetadata": importlib.metadata.PackageMetadata}
