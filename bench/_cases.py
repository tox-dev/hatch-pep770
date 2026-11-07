"""
The timed paths: each case turns the fixtures into an untimed reset and a timed step.

A case runs in its own pyperf process tree, so module caches one case fills never speed up another. Steady-state cases
time the step in a warm process, as a build backend or a long-lived tool sees it; the ``cold-`` cases time a fresh
``python -m python_sbom`` process, imports and schema loading included, as a shell user sees it.
"""

from __future__ import annotations

import contextlib
import importlib
import importlib.util
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


@dataclass(frozen=True, slots=True, kw_only=True)
class Step:
    run: Callable[[], None]
    #: undoes what ``run`` changed on disk, untimed, before every call
    reset: Callable[[], None] = lambda: None
    #: the command a cold case runs, which the profiler runs under cProfile instead of profiling the subprocess call
    command: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Case:
    tier: str
    needs: tuple[str, ...]
    make: Callable[[dict[str, str], Path], Step]


def _hatch(root_key: str, *, hooks: bool) -> Callable[[dict[str, str], Path], Step]:
    def make(fixtures: dict[str, str], scratch: Path) -> Step:
        from hatchling.builders.wheel import WheelBuilder  # ruff: ignore[import-outside-top-level] # only hatch cases

        if not hooks:
            os.environ["HATCH_BUILD_NO_HOOKS"] = "true"
        root = fixtures[root_key]

        def run() -> None:
            list(WheelBuilder(root).build(directory=str(scratch), versions=["standard"]))

        return Step(run=run, reset=lambda: _empty(scratch))

    return make


def _embed(*, cold: bool) -> Callable[[dict[str, str], Path], Step]:
    def make(fixtures: dict[str, str], scratch: Path) -> Step:
        wheel = scratch / Path(fixtures["meson-wheel"]).name
        arguments = ("embed", str(wheel), "--root", fixtures["meson"], "--build-env", fixtures["fat-env"])

        def reset() -> None:
            shutil.copyfile(fixtures["meson-wheel"], wheel)

        return Step(
            run=_cold(arguments) if cold else _cli(arguments),
            reset=reset,
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

    def run() -> None:
        # no revision, so only reading the environment's distributions is timed
        collect_facts(root, lambda _root: None, path=path)

    return Step(run=run)


def _bundled(key: str) -> Callable[[dict[str, str], Path], Step]:
    def make(fixtures: dict[str, str], scratch: Path) -> Step:  # ruff: ignore[unused-function-argument] # one signature
        # revisions before the move keep the reader in _collect._source, and those before the batch reader take one
        # wheel's bytes rather than a list and a way to open each
        moved = importlib.util.find_spec("python_sbom._wheel._bundled") is not None
        module = importlib.import_module("python_sbom._wheel._bundled" if moved else "python_sbom._collect._source")
        wheel = Path(fixtures[key])
        data = wheel.read_bytes()
        if (single := getattr(module, "read_bundled_wheel", None)) is not None:
            return Step(run=lambda: single(data, wheel.name))
        batch = module.read_bundled_wheels
        return Step(run=lambda: batch([wheel.name], lambda _name: io.BytesIO(data)))

    return make


CASES: Final[dict[str, Case]] = {
    "hatch-small": Case(tier="slow", needs=("small",), make=_hatch("small", hooks=True)),
    "hatch-small-nohook": Case(tier="slow", needs=("small",), make=_hatch("small", hooks=False)),
    "hatch-virtualenv": Case(tier="slow", needs=("virtualenv",), make=_hatch("virtualenv", hooks=True)),
    "hatch-virtualenv-nohook": Case(tier="slow", needs=("virtualenv",), make=_hatch("virtualenv", hooks=False)),
    "embed-meson-fat-env": Case(tier="slow", needs=("meson", "meson-wheel", "fat-env"), make=_embed(cold=False)),
    "cold-embed-meson-fat-env": Case(tier="slow", needs=("meson", "meson-wheel", "fat-env"), make=_embed(cold=True)),
    "archive-zipapp": Case(tier="slow", needs=("virtualenv", "zipapp"), make=_archive),
    "validate-own-wheel": Case(tier="slow", needs=("own-wheel",), make=_validate("own-wheel")),
    "cold-validate-own-wheel": Case(tier="slow", needs=("own-wheel",), make=_cold_validate),
    # virtualenv's SBOMs list over 5,000 components, files included, so a limit above that times the full check
    "validate-virtualenv-wheel": Case(
        tier="slow", needs=("virtualenv-wheel",), make=_validate("virtualenv-wheel", max_components=20_000)
    ),
    "validate-zipapp": Case(
        tier="slow", needs=("zipapp-embedded",), make=_validate("zipapp-embedded", max_components=20_000)
    ),
    # at the default cap, so every revision times the full schema check
    "validate-hostile-5k": Case(tier="huge", needs=("hostile-5k",), make=_validate("hostile-5k", expect_valid=False)),
    # the default limit: a revision with the component cap times the rejection, one without the full schema check
    "validate-hostile-10k": Case(
        tier="huge", needs=("hostile-10k",), make=_validate("hostile-10k", expect_valid=False)
    ),
    # a limit above the count, so every revision times the full schema check
    "validate-hostile-10k-uncapped": Case(
        tier="huge", needs=("hostile-10k",), make=_validate("hostile-10k", expect_valid=False, max_components=20_000)
    ),
    "spdx-zipapp": Case(tier="fast", needs=("zipapp-sbom",), make=_spdx),
    "collect-facts-fat-env": Case(tier="slow", needs=("meson", "fat-env"), make=_collect_facts),
    "bundled-wheel-pip": Case(tier="fast", needs=("pip-wheel",), make=_bundled("pip-wheel")),
    "bundled-wheel-setuptools": Case(tier="fast", needs=("setuptools-wheel",), make=_bundled("setuptools-wheel")),
}


def make_step(name: str, fixtures: dict[str, str], scratch: Path) -> Step:
    os.environ["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    case = CASES[name]
    if missing := [key for key in case.needs if key not in fixtures]:
        msg = f"{name} needs the fixture(s) {', '.join(missing)}; prepare with --virtualenv to build them"
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


def _cold(arguments: tuple[str, ...]) -> Callable[[], None]:
    command = _command(arguments)

    def run() -> None:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)

    return run


def _empty(directory: Path) -> None:
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)


__all__ = [
    "CASES",
    "TIERS",
    "Step",
    "make_step",
]
