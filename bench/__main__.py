"""
CLI entry point: ``python -m bench <command>``, run from the project root or with the root on ``PYTHONPATH``.

``prepare`` builds the fixtures into the work directory, the only command that needs the network. ``run`` times each
case in its own pyperf process tree, one JSON file per case under ``<out>/<python>/``; options after ``--`` reach pyperf
and override the case's defaults (e.g. ``--rigorous``).

``profile`` runs each case once under cProfile after an untimed warm-up, and under py-spy with ``--py-spy``. ``report``
renders pyperf JSON as a Markdown table, ``compare`` two result directories side by side, and ``list`` prints the cases.

The timed process imports whichever python-sbom the running interpreter has installed, so comparing two revisions means
running the same harness from two environments.
"""

from __future__ import annotations

import argparse
import cProfile
import io
import os
import pstats
import shutil
import subprocess
import sys
import tempfile
import time
from importlib.metadata import version
from operator import itemgetter
from pathlib import Path
from typing import TYPE_CHECKING, Final

from ._cases import CASES, TIERS, make_step
from ._fixtures import load, prepare

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from ._cases import Step

_ROOT: Final[Path] = Path(__file__).parents[1]
_PYTHON: Final[str] = f"{sys.implementation.name}{sys.version_info.major}.{sys.version_info.minor}"


def main(arguments: Sequence[str]) -> None:
    if arguments[:1] == ["worker"]:
        _worker(arguments[1], Path(arguments[2]), arguments[3], arguments[4:])
        return
    passthrough: list[str] = []
    if "--" in arguments:
        split = arguments.index("--")
        arguments, passthrough = arguments[:split], list(arguments[split + 1 :])
    options = _parser().parse_args(arguments)
    match options.command:
        case "prepare":
            prepare(options.work, options.project, options.virtualenv)
        case "run":
            out = options.out / (_PYTHON if options.clock == "wall" else f"{_PYTHON}-{options.clock}")
            _run(options.work, out, _selected(options.cases), options.clock, passthrough)
        case "profile":
            _profile(options.work, options.out / _PYTHON / "profile", _selected(options.cases), py_spy=options.py_spy)
        case "once":
            _once(options.case, options.work, options.cprofile)
        case "report":
            sys.stdout.write(_report(options.paths))
        case "compare":
            sys.stdout.write(_compare(options.before, options.current))
        case "list":
            sys.stdout.write("".join(f"{name}\n" for name in CASES))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m bench")
    commands = parser.add_subparsers(dest="command", required=True)
    work = argparse.ArgumentParser(add_help=False)
    work.add_argument("--work", type=Path, default=_ROOT / ".tox" / "bench-work", help="fixture directory")
    output = argparse.ArgumentParser(add_help=False)
    output.add_argument("--out", type=Path, default=_ROOT / ".tox" / "bench-results", help="result directory")
    setup = commands.add_parser("prepare", parents=[work], help="build the fixtures")
    setup.add_argument("--project", type=Path, default=_ROOT, help="python-sbom checkout whose own wheel to build")
    setup.add_argument("--virtualenv", type=Path, help="virtualenv checkout carrying [tool.python-sbom]")
    for name, text in (("run", "time cases with pyperf"), ("profile", "profile cases once")):
        command = commands.add_parser(name, parents=[work, output], help=text)
        command.add_argument("cases", nargs="*", metavar="CASE", help="cases to run (default: all)")
    commands.choices["run"].add_argument(
        "--clock",
        choices=("wall", "cpu"),
        default="wall",
        help="wall time, or the CPU time of the process and its children, steadier on a loaded machine",
    )
    commands.choices["profile"].add_argument("--py-spy", action="store_true", help="also record with py-spy")
    once = commands.add_parser("once", parents=[work], help="run one case once, for a profiler")
    once.add_argument("case")
    once.add_argument("--cprofile", type=Path, metavar="STATS", help="run it under cProfile, writing its stats here")
    commands.add_parser("report", help="render results as Markdown").add_argument("paths", nargs="+", type=Path)
    compare = commands.add_parser("compare", help="render two result directories side by side as Markdown")
    compare.add_argument("before", type=Path, help="result directory of the baseline")
    compare.add_argument("current", type=Path, help="result directory of the revision under test")
    commands.add_parser("list", help="print the case names")
    return parser


def _selected(names: list[str]) -> list[str]:
    if unknown := sorted(set(names) - CASES.keys()):
        msg = f"unknown case(s) {', '.join(unknown)}; known: {', '.join(CASES)}"
        raise SystemExit(msg)
    return names or list(CASES)


def _run(work: Path, out: Path, names: list[str], clock: str, passthrough: list[str]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    fixtures: Final = load(work)
    for name in names:
        if missing := [key for key in CASES[name].needs if key not in fixtures]:
            sys.stdout.write(f"skip {name}: no fixture {', '.join(missing)}\n")
            continue
        (result := out / f"{name}.json").unlink(missing_ok=True)
        subprocess.run(
            [
                sys.executable,
                "-m",
                "bench",
                "worker",
                name,
                str(work),
                clock,
                "--output",
                str(result),
                "--inherit-environ",
                "PYTHONPATH",
                *TIERS[CASES[name].tier],
                *passthrough,
            ],
            check=True,
        )


def _worker(name: str, work: Path, clock: str, arguments: Sequence[str]) -> None:
    import pyperf  # ruff: ignore[import-outside-top-level] # only the timed processes need it

    runner = pyperf.Runner(program_args=("-m", "bench", "worker", name, str(work), clock))
    runner.parse_args(list(arguments))
    with tempfile.TemporaryDirectory(dir=work, prefix="scratch-") as scratch:
        step = make_step(name, load(work), Path(scratch))
        runner.metadata["python_sbom_version"] = version("python-sbom")
        runner.metadata["bench_clock"] = clock
        runner.bench_time_func(name, _timed, step, time.perf_counter if clock == "wall" else _cpu_time)


def _timed(loops: int, step: Step, clock: Callable[[], float]) -> float:
    total = 0.0
    for _ in range(loops):
        step.reset()
        start = clock()
        step.run()
        total += clock() - start
    return total


def _cpu_time() -> float:
    # children count once waited for, which covers git and the cold cases' interpreter
    import resource  # ruff: ignore[import-outside-top-level] # Unix only, and only the cpu clock needs it

    own, children = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime + own.ru_stime + children.ru_utime + children.ru_stime


def _profile(work: Path, out: Path, names: list[str], *, py_spy: bool) -> None:
    out.mkdir(parents=True, exist_ok=True)
    fixtures: Final = load(work)
    summary: Final[list[str]] = []
    for name in names:
        if any(key not in fixtures for key in CASES[name].needs):
            continue
        stats_file = out / f"{name}.pstats"
        # each case in a fresh process, so one case's warm caches never shorten another's profile
        subprocess.run(
            [sys.executable, "-m", "bench", "once", name, "--work", str(work), "--cprofile", str(stats_file)],
            check=True,
        )
        summary.append(_hot_spots(name, stats_file))
        (out / f"{name}.txt").write_text(_stats_text(stats_file), encoding="utf-8")
        # next to the interpreter too, as a venv's scripts are when its python runs without activating it
        if py_spy and (
            spy := shutil.which("py-spy", path=f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}")
        ):
            subprocess.run(
                [
                    spy,
                    "record",
                    "--format",
                    "speedscope",
                    "--rate",
                    "500",
                    "--output",
                    str(out / f"{name}.speedscope.json"),
                    "--",
                    sys.executable,
                    "-m",
                    "bench",
                    "once",
                    name,
                    "--work",
                    str(work),
                ],
                check=True,
            )
    (target := out / "hot-spots.md").write_text("\n".join(summary), encoding="utf-8")
    sys.stdout.write(f"wrote {target}\n")


# a helper of main's because, inlined into main, it pushes main over ruff's C901 complexity limit
def _once(name: str, work: Path, stats_file: Path | None) -> None:  # simplint: ignore[SMP505] # see above
    # without a stats file for an outside profiler such as py-spy
    with tempfile.TemporaryDirectory(dir=work, prefix="scratch-") as scratch:
        step = make_step(name, load(work), Path(scratch))
        step.reset()
        if stats_file is None:
            step.run()
            return
        if step.command is not None:
            command = [step.command[0], "-m", "cProfile", "-o", str(stats_file), *step.command[1:]]
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
            return
        if CASES[name].tier != "huge":  # warm, as the timed values are; huge values are each a process's first call
            step.run()
            step.reset()
        profiler = cProfile.Profile()
        profiler.runcall(step.run)
        profiler.dump_stats(stats_file)


def _stats_text(stats_file: Path) -> str:
    buffer = io.StringIO()
    stats = pstats.Stats(str(stats_file), stream=buffer)
    stats.sort_stats("cumulative").print_stats(40)
    stats.sort_stats("tottime").print_stats(40)
    return buffer.getvalue()


def _hot_spots(name: str, stats_file: Path) -> str:
    entries = pstats.Stats(str(stats_file)).stats  # ty: ignore[unresolved-attribute] # the table pstats keeps is not in its stubs
    total = sum(entry[2] for entry in entries.values()) or 1.0
    rows = [
        (_label(function), entry[1], entry[0], entry[2], entry[3])
        for function, entry in entries.items()
        if not _harness(function)
    ]
    lines = [f"### {name}", "", f"profiled total {total:.3f}s", ""]
    for title, key in (("cumulative", 4), ("own time", 3)):
        lines += [
            f"by {title}:",
            "",
            "| function | calls | own s | cumulative s | cumulative % |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
        lines += [
            f"| `{label}` | {calls if calls == primitive else f'{calls}/{primitive}'} | {own:.3f} | {cumulative:.3f} |"
            f" {100 * cumulative / total:.1f} |"
            for label, calls, primitive, own, cumulative in sorted(rows, key=itemgetter(key), reverse=True)[:15]
        ]
        lines.append("")
    return "\n".join(lines)


def _harness(function: tuple[str, int, str]) -> bool:
    file, _, func = function
    return Path(file).parent == Path(__file__).parent or func in {
        "<built-in method builtins.exec>",
        "<method 'disable' of '_lsprof.Profiler' objects>",
    }


def _label(function: tuple[str, int, str]) -> str:
    file, line, func = function
    if file == "~":
        return func
    parts = Path(file).parts
    for anchor in ("site-packages", "lib"):
        if anchor in parts:
            parts = parts[len(parts) - parts[::-1].index(anchor) :]
            break
    return f"{'/'.join(parts[-3:])}:{line}({func})"


def _report(paths: list[Path]) -> str:
    import pyperf  # ruff: ignore[import-outside-top-level] # see _worker

    files = sorted(file for path in paths for file in (path.glob("*.json") if path.is_dir() else [path]))
    lines = [
        "| path | python | median | IQR (p25 - p75) | min - max | values |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for file in files:
        benchmark = pyperf.Benchmark.load(str(file))
        values = benchmark.get_values()
        python = benchmark.get_metadata().get("python_version", "?")
        lines.append(
            f"| {benchmark.get_name()} | {python} | {_seconds(benchmark.median())} |"
            f" {_seconds(benchmark.percentile(25))} - {_seconds(benchmark.percentile(75))} |"
            f" {_seconds(min(values))} - {_seconds(max(values))} | {len(values)} |"
        )
    return "".join(f"{line}\n" for line in lines)


def _compare(before: Path, current: Path) -> str:
    import pyperf  # ruff: ignore[import-outside-top-level] # see _worker

    lines = [
        "| path | before median ± MAD | current median ± MAD | change |",
        "| --- | ---: | ---: | ---: |",
    ]
    for name in sorted({file.stem for file in (*before.glob("*.json"), *current.glob("*.json"))}):
        old, new = (
            pyperf.Benchmark.load(str(file)) if (file := directory / f"{name}.json").is_file() else None
            for directory in (before, current)
        )
        # the median absolute deviation, which one value a loaded host stretched barely moves
        cells = [
            "-" if benchmark is None else f"{_seconds(benchmark.median())} ± {_seconds(benchmark.median_abs_dev())}"
            for benchmark in (old, new)
        ]
        change = "-" if old is None or new is None else _change(old.median(), new.median())
        lines.append(f"| {name} | {cells[0]} | {cells[1]} | {change} |")
    return "".join(f"{line}\n" for line in lines)


def _change(before: float, current: float) -> str:
    ratio = before / current
    return f"{ratio:.2f}x faster" if ratio >= 1 else f"{1 / ratio:.2f}x slower"


def _seconds(value: float) -> str:
    return f"{value:.2f} s" if value >= 1 else f"{value * 1000:.1f} ms"


if __name__ == "__main__":
    main(sys.argv[1:])
