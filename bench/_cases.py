"""
The timed paths: each case turns the fixtures into an untimed reset and a timed step.

A case runs in its own pyperf process tree, so module caches one case fills never speed up another. Steady-state cases
time the step in a warm process, as a build backend or a long-lived tool sees it; the ``cold-`` cases time a fresh
``python -m python_sbom`` process, imports and schema loading included, as a shell user sees it.
"""

from __future__ import annotations

import contextlib
import inspect
import io
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

from ._fixtures import SOURCE_DATE_EPOCH

if TYPE_CHECKING:
    from collections.abc import Callable

#: pyperf options per cost: many calibrated loops for cheap steps, fewer single-loop values for slow ones
TIERS: Final[dict[str, tuple[str, ...]]] = {
    "fast": ("--processes", "10", "--values", "5", "--warmups", "1"),
    "slow": ("--processes", "6", "--values", "3", "--warmups", "1", "--loops", "1"),
    "huge": ("--processes", "3", "--values", "1", "--warmups", "0", "--loops", "1"),
}


@dataclass(frozen=True)
class Step:
    run: Callable[[], object]
    reset: Callable[[], object] | None = None
    #: the command a cold case runs, which the profiler runs under cProfile instead of profiling the subprocess call
    command: tuple[str, ...] | None = None


@dataclass(frozen=True)
class Case:
    name: str
    tier: str
    needs: tuple[str, ...]
    make: Callable[[dict[str, str], Path], Step]


def _hatch(root_key: str, *, hooks: bool) -> Callable[[dict[str, str], Path], Step]:
    def make(fixtures: dict[str, str], scratch: Path) -> Step:
        from hatchling.builders.wheel import WheelBuilder  # ruff: ignore[import-outside-top-level] # only hatch cases

        if not hooks:
            os.environ["HATCH_BUILD_NO_HOOKS"] = "true"
        root = fixtures[root_key]
        return Step(
            run=lambda: list(WheelBuilder(root).build(directory=str(scratch), versions=["standard"])),
            reset=lambda: _empty(scratch),
        )

    return make


def _embed(*, cold: bool) -> Callable[[dict[str, str], Path], Step]:
    def make(fixtures: dict[str, str], scratch: Path) -> Step:
        wheel = scratch / Path(fixtures["meson-wheel"]).name
        arguments = ("embed", str(wheel), "--root", fixtures["meson"], "--build-env", fixtures["fat-env"])
        return Step(
            run=_cold(arguments) if cold else _cli(arguments),
            reset=lambda: shutil.copyfile(fixtures["meson-wheel"], wheel),
            command=_command(arguments) if cold else None,
        )

    return make


def _archive(fixtures: dict[str, str], scratch: Path) -> Step:
    return Step(
        run=_cli((
            "archive",
            fixtures["zipapp"],
            "--root",
            fixtures["virtualenv"],
            "--build-script",
            "tasks/make_zipapp.py",
            "--output",
            str(scratch / "virtualenv.pyz.cdx.json"),
        ))
    )


def _validate(
    key: str, *, expect_valid: bool = True, max_components: int | None = None
) -> Callable[[dict[str, str], Path], Step]:
    def make(fixtures: dict[str, str], scratch: Path) -> Step:  # ruff: ignore[unused-function-argument] # one signature
        from python_sbom._validate._artifact import validate  # ruff: ignore[import-outside-top-level] # loads the schema

        path = Path(fixtures[key])
        # revisions before the component cap take no limit and check any count, which is what a raised limit times
        limit = (
            ()
            if max_components is None or "max_components" not in inspect.signature(validate).parameters
            else (max_components,)
        )

        def run() -> None:
            if (problems := validate(path, None, *limit)) and expect_valid:
                msg = f"{path.name} is invalid: {problems}"
                raise RuntimeError(msg)

        return Step(run=run)

    return make


def _cold_validate(fixtures: dict[str, str], scratch: Path) -> Step:  # ruff: ignore[unused-function-argument] # one signature
    arguments = ("validate", fixtures["own-wheel"])
    return Step(run=_cold(arguments), command=_command(arguments))


def _spdx(fixtures: dict[str, str], scratch: Path) -> Step:
    return Step(run=_cli(("spdx", fixtures["zipapp-sbom"], str(scratch / "virtualenv.spdx.json"))))


def _collect_facts(fixtures: dict[str, str], scratch: Path) -> Step:  # ruff: ignore[unused-function-argument] # one signature
    from python_sbom._collect._facts import collect_facts  # ruff: ignore[import-outside-top-level] # see _validate

    root, path = Path(fixtures["meson"]), [fixtures["fat-env"]]
    # no revision, so only reading the environment's distributions is timed
    return Step(run=lambda: collect_facts(root, lambda _root: None, path=path))


def _bundled(key: str) -> Callable[[dict[str, str], Path], Step]:
    def make(fixtures: dict[str, str], scratch: Path) -> Step:  # ruff: ignore[unused-function-argument] # one signature
        from python_sbom._collect._source import read_bundled_wheel  # ruff: ignore[import-outside-top-level] # see _validate

        wheel = Path(fixtures[key])
        data = wheel.read_bytes()
        return Step(run=lambda: read_bundled_wheel(data, wheel.name))

    return make


CASES: Final[dict[str, Case]] = {
    case.name: case
    for case in (
        Case("hatch-small", "slow", ("small",), _hatch("small", hooks=True)),
        Case("hatch-small-nohook", "slow", ("small",), _hatch("small", hooks=False)),
        Case("hatch-virtualenv", "slow", ("virtualenv",), _hatch("virtualenv", hooks=True)),
        Case("hatch-virtualenv-nohook", "slow", ("virtualenv",), _hatch("virtualenv", hooks=False)),
        Case("embed-meson-fat-env", "slow", ("meson", "meson-wheel", "fat-env"), _embed(cold=False)),
        Case("cold-embed-meson-fat-env", "slow", ("meson", "meson-wheel", "fat-env"), _embed(cold=True)),
        Case("archive-zipapp", "slow", ("virtualenv", "zipapp"), _archive),
        Case("validate-own-wheel", "slow", ("own-wheel",), _validate("own-wheel")),
        Case("cold-validate-own-wheel", "slow", ("own-wheel",), _cold_validate),
        Case("validate-virtualenv-wheel", "slow", ("virtualenv-wheel",), _validate("virtualenv-wheel")),
        Case("validate-zipapp", "slow", ("zipapp-embedded",), _validate("zipapp-embedded")),
        # the default limit: a revision with the component cap times the rejection, one without the full schema check
        Case("validate-hostile-10k", "huge", ("hostile",), _validate("hostile", expect_valid=False)),
        # a limit above the count, so every revision times the full schema check
        Case(
            "validate-hostile-10k-uncapped",
            "huge",
            ("hostile",),
            _validate("hostile", expect_valid=False, max_components=20_000),
        ),
        Case("spdx-zipapp", "fast", ("zipapp-sbom",), _spdx),
        Case("collect-facts-fat-env", "slow", ("meson", "fat-env"), _collect_facts),
        Case("bundled-wheel-pip", "fast", ("pip-wheel",), _bundled("pip-wheel")),
        Case("bundled-wheel-setuptools", "fast", ("setuptools-wheel",), _bundled("setuptools-wheel")),
    )
}


def make_step(case: Case, fixtures: dict[str, str], scratch: Path) -> Step:
    os.environ["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    if missing := [key for key in case.needs if key not in fixtures]:
        msg = f"{case.name} needs the fixture(s) {', '.join(missing)}; prepare with --virtualenv to build them"
        raise SystemExit(msg)
    return case.make(fixtures, scratch)


def _cli(arguments: tuple[str, ...]) -> Callable[[], None]:
    from python_sbom._cli._main import main  # ruff: ignore[import-outside-top-level] # see _validate

    def run() -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            main(list(arguments))

    return run


def _command(arguments: tuple[str, ...]) -> tuple[str, ...]:
    return (sys.executable, "-m", "python_sbom", *arguments)


def _cold(arguments: tuple[str, ...]) -> Callable[[], object]:
    command = _command(arguments)
    return lambda: subprocess.run(command, check=True, stdout=subprocess.DEVNULL)


def _empty(directory: Path) -> None:
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)


__all__ = [
    "CASES",
    "TIERS",
    "Case",
    "Step",
    "make_step",
]
