from __future__ import annotations

import collections.abc
import functools
import importlib
import inspect
import pathlib
import pkgutil
import typing
from typing import TYPE_CHECKING, Final

import pytest

import python_sbom
import python_sbom.hatch
from python_sbom import Settings
from python_sbom._model._inputs import RecordRow
from python_sbom._model._metadata import CoreMetadata

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

_Hint = object  # simplint: ignore[SMP602] # hints are arbitrary typing objects

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


def reached(start: _Hint) -> set[_Hint]:
    # every python_sbom type a hint of a public name leads to, through fields, members and nested hints; a private type
    # ends the walk there, so the leak is what gets reported even when its own hints do not resolve
    found: set[_Hint] = set()
    pending: list[_Hint] = [start]
    public = exported()
    while pending:
        if (item := pending.pop()) in found:
            continue
        found.add(item)
        if _ours(item) and item not in public:
            continue
        if inspect.isclass(item):
            pending.extend(typing.get_type_hints(item, globalns=_names(), include_extras=True).values())
            for member in _members(item):
                pending.extend(typing.get_type_hints(member, globalns=_names(), include_extras=True).values())
        # a Callable's parameters come as one list among its arguments
        for argument in typing.get_args(item):
            pending.extend(argument if isinstance(argument, list) else [argument])
        if (origin := typing.get_origin(item)) is not None:
            pending.append(origin)
    return {item for item in found if _ours(item)}


def _members(cls: type) -> Iterator[_Hint]:
    # read the class dictionaries, since attribute access hides a property's getter and unwraps class and static methods
    for owner in inspect.getmro(cls):
        if not _ours(owner):
            continue
        for value in owner.__dict__.values():
            match value:
                case property():
                    yield value.fget
                case classmethod() | staticmethod():
                    yield value.__func__
                case functools.cached_property():
                    yield value.func
                case _ if inspect.isfunction(value):
                    yield value


def _ours(item: _Hint) -> bool:
    return getattr(item, "__module__", "").startswith("python_sbom")


@pytest.mark.parametrize("name", sorted(_PUBLIC - {"__version__"}), ids=str)
def test_public_types_only_reach_public_types(name: str) -> None:
    assert reached(getattr(python_sbom, name)) - exported() == set()


def test_hook_only_reaches_public_types() -> None:
    assert reached(python_sbom.hatch.SbomBuildHook) - exported() == set()


@pytest.mark.parametrize(
    "wrap",
    [
        pytest.param(property, id="property"),
        pytest.param(functools.cached_property, id="cached_property"),
        pytest.param(classmethod, id="classmethod"),
        pytest.param(staticmethod, id="staticmethod"),
    ],
)
def test_closure_reports_private_member_types(
    monkeypatch: pytest.MonkeyPatch, wrap: Callable[[Callable[[Settings], RecordRow]], _Hint]
) -> None:
    def leak(_: Settings) -> RecordRow:
        raise NotImplementedError

    monkeypatch.setattr(Settings, "leak", wrap(leak), raising=False)
    assert reached(Settings) - exported() == {RecordRow}


def test_closure_reports_private_type_with_unresolved_hints(monkeypatch: pytest.MonkeyPatch) -> None:
    # CoreMetadata names packaging's RawMetadata, which no python_sbom module imports at runtime
    def leak(_: Settings) -> CoreMetadata:
        raise NotImplementedError

    monkeypatch.setattr(Settings, "leak", property(leak), raising=False)
    assert reached(Settings) - exported() == {CoreMetadata}


def exported() -> set[_Hint]:
    return {getattr(python_sbom, name) for name in _PUBLIC} | {python_sbom.hatch.SbomBuildHook}


def _names() -> dict[str, _Hint]:
    # the annotations name types the modules import only for type checking, so every module's names resolve them
    modules = [
        pathlib,
        collections.abc,
        typing,
        *(importlib.import_module(found.name) for found in pkgutil.walk_packages(python_sbom.__path__, "python_sbom.")),
    ]
    return dict(member for module in modules for member in inspect.getmembers(module))
