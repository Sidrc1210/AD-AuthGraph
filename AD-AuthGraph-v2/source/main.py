"""
main.py - AD-AuthGraph-v2 pipeline entry point.

Runs the v2 workflow:
    C# collector -> graph_builder.py -> analyzer.exe/analyzer ->
    refiner.py -> visualizer.py

The collector and analyzer are external executables. The graph builder is used
from graph_builder.py directly so output-directory naming remains deterministic
without copying enterprise-size state JSON files.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_STATE_NAME = "ad_authorization_state.json"


class PipelineError(RuntimeError):
    """Raised when a pipeline stage cannot complete."""


@dataclass(frozen=True)
class PipelinePaths:
    """All derived files for one state snapshot."""

    state: Path
    output_dir: Path
    graph: Path
    analysis: Path
    refined: Path
    report: Path

    @classmethod
    def from_state(cls, state: Path, output_dir: Optional[Path] = None) -> "PipelinePaths":
        state = state.expanduser().resolve()
        out = (output_dir.expanduser().resolve() if output_dir else state.parent)
        stem = state.stem
        return cls(
            state=state,
            output_dir=out,
            graph=out / f"{stem}_graph.json",
            analysis=out / f"{stem}_analysis.json",
            refined=out / f"{stem}_refined.json",
            report=out / f"{stem}_report_refined.html",
        )


@dataclass
class RunContext:
    """Runtime settings shared by stages."""

    verbose: bool
    dry_run: bool = False


def banner(title: str, verbose: bool = True) -> None:
    """Print a visible section banner."""

    if verbose:
        print("=" * 80)
        print(title)
        print("=" * 80)


def divider(verbose: bool = True) -> None:
    """Print a stage divider."""

    if verbose:
        print("-" * 80)


def log(message: str = "", verbose: bool = True) -> None:
    """Print a progress message when verbose output is enabled."""

    if verbose:
        print(message)


def format_duration(seconds: float) -> str:
    """Return a human-friendly duration."""

    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {secs:.1f}s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h {int(minutes)}m {secs:.1f}s"


def resolve_existing_file(path: Path, description: str) -> Path:
    """Resolve an input path and fail with a useful message when missing."""

    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise PipelineError(f"{description} not found: {resolved}")
    if not resolved.is_file():
        raise PipelineError(f"{description} is not a file: {resolved}")
    return resolved


def ensure_script(path: Path, name: str) -> Path:
    """Return a required script path."""

    if not path.exists():
        raise PipelineError(f"Missing {name}: {path}")
    return path


def resolve_tool(explicit: Optional[str], names: Sequence[str], hint: str) -> Path:
    """Resolve a local or PATH executable."""

    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.exists():
            return candidate.resolve()
        found = shutil.which(explicit)
        if found:
            return Path(found).resolve()
        raise PipelineError(f"Executable not found: {explicit}\n{hint}")

    for name in names:
        local = SCRIPT_DIR / name
        if local.exists():
            return local.resolve()
        found = shutil.which(name)
        if found:
            return Path(found).resolve()

    raise PipelineError(
        "Missing executable. Tried: "
        + ", ".join(names)
        + "\n"
        + hint
    )


def default_analyzer_names() -> List[str]:
    """Return analyzer executable names for this platform."""

    if os.name == "nt":
        return ["analyzer.exe"]
    return ["analyzer"]


def default_collector_names() -> List[str]:
    """Return collector executable names for this platform."""

    if os.name == "nt":
        return ["ADAuthCollector.exe", "Program.exe", "collect-adauth-csharp.exe"]
    return ["ADAuthCollector", "Program", "collect-adauth-csharp"]


def command_text(cmd: Sequence[object]) -> str:
    """Render a command for logs."""

    return " ".join(str(part) for part in cmd)


def run_process(
    cmd: Sequence[object],
    ctx: RunContext,
    *,
    cwd: Path = SCRIPT_DIR,
    capture: bool = False,
    stage: str = "command",
) -> str:
    """Run a subprocess and raise PipelineError on non-zero exit."""

    rendered = command_text(cmd)
    log(f"    $ {rendered}", ctx.verbose)
    if ctx.dry_run:
        return ""

    if capture:
        result = subprocess.run(
            [str(part) for part in cmd],
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    elif ctx.verbose:
        result = subprocess.run([str(part) for part in cmd], cwd=str(cwd), check=False)
    else:
        result = subprocess.run(
            [str(part) for part in cmd],
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    if result.returncode != 0:
        details = [f"{stage} failed with exit code {result.returncode}."]
        if getattr(result, "stdout", None):
            details.append("\nstdout:\n" + result.stdout.strip())
        if getattr(result, "stderr", None):
            details.append("\nstderr:\n" + result.stderr.strip())
        raise PipelineError("\n".join(details))

    if not ctx.verbose and not capture:
        return ""
    return result.stdout if capture else ""


def parse_collector_output_arg(args: Sequence[str]) -> Optional[Path]:
    """Find an output path already supplied in forwarded collector args."""

    output_flags = {"--output", "--output-path", "--output-file"}
    i = 0
    while i < len(args):
        token = args[i]
        for flag in output_flags:
            if token == flag and i + 1 < len(args):
                return Path(args[i + 1])
            if token.startswith(flag + "="):
                return Path(token.split("=", 1)[1])
        i += 1
    return None


def inject_collector_output(args: Sequence[str], state_path: Path) -> List[str]:
    """Add --output when the caller did not supply a collector output path."""

    forwarded = list(args)
    if parse_collector_output_arg(forwarded) is None:
        forwarded.extend(["--output", str(state_path)])
    return forwarded


def output_dir_for_collect(args_output_dir: Optional[str]) -> Path:
    """Choose the output directory for collect/pipeline defaults."""

    return Path(args_output_dir).expanduser().resolve() if args_output_dir else Path.cwd().resolve()


def collector_state_path(args_state: Optional[str], args_output_dir: Optional[str], collector_args: Sequence[str]) -> Path:
    """Determine the state JSON path produced by the collector."""

    explicit = parse_collector_output_arg(collector_args)
    if explicit is not None:
        return explicit.expanduser().resolve()
    if args_state:
        return Path(args_state).expanduser().resolve()
    return output_dir_for_collect(args_output_dir) / DEFAULT_STATE_NAME


def build_graph(paths: PipelinePaths, ctx: RunContext, step: str = "1/4") -> None:
    """Run graph_builder.py functionality and write the requested graph JSON."""

    banner(f"[STEP {step}] Building Authorization Graph", ctx.verbose)
    divider(ctx.verbose)
    resolve_existing_file(paths.state, "State JSON")
    ensure_script(SCRIPT_DIR / "graph_builder.py", "graph_builder.py")
    paths.output_dir.mkdir(parents=True, exist_ok=True)

    if ctx.dry_run:
        log(f"    would build {paths.graph}", ctx.verbose)
        return

    try:
        from graph_builder import AuthorizationGraph
    except Exception as exc:
        raise PipelineError(f"Failed to import graph_builder.py: {exc}") from exc

    graph = AuthorizationGraph()
    if not graph.load_from_json(str(paths.state)):
        raise PipelineError(f"graph_builder.py failed to load: {paths.state}")
    if not graph.export_graph_data(str(paths.graph)):
        raise PipelineError(f"graph_builder.py failed to export: {paths.graph}")

    stats = graph.get_statistics()
    log("[+] Graph exported: " + str(paths.graph), ctx.verbose)
    log(
        "    Nodes: {nodes}  Edges: {edges}  Users: {users}  Groups: {groups}  Computers: {computers}".format(
            nodes=stats.get("nodes", 0),
            edges=stats.get("edges", 0),
            users=stats.get("users", 0),
            groups=stats.get("groups", 0),
            computers=stats.get("computers", 0),
        ),
        ctx.verbose,
    )
    log("", ctx.verbose)


def run_collector(
    args: argparse.Namespace,
    collector_args: Sequence[str],
    ctx: RunContext,
) -> Path:
    """Run the C# AD collector and return its state JSON path."""

    banner("[STEP 1/5] Running C# Collector", ctx.verbose)
    divider(ctx.verbose)

    collector = resolve_tool(
        args.collector_exe,
        default_collector_names(),
        "Build Program.cs as ADAuthCollector.exe or Program.exe, or pass --collector-exe PATH.",
    )
    state_path = collector_state_path(args.state_json, args.output_dir, collector_args)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    forwarded = inject_collector_output(collector_args, state_path)

    log(f"Collector: {collector}", ctx.verbose)
    log(f"State JSON: {state_path}", ctx.verbose)
    run_process([collector, *forwarded], ctx, cwd=Path.cwd().resolve(), stage="collector")

    if not ctx.dry_run:
        resolve_existing_file(state_path, "Collector output")
    log("[+] Collection complete: " + str(state_path), ctx.verbose)
    log("", ctx.verbose)
    return state_path


def run_analyzer(paths: PipelinePaths, analyzer_exe: Optional[str], analyzer_args: Sequence[str], ctx: RunContext, step: str) -> None:
    """Run analyzer.exe/analyzer against a graph JSON file."""

    banner(f"[STEP {step}] Analyzing Authorization Graph", ctx.verbose)
    divider(ctx.verbose)
    resolve_existing_file(paths.graph, "Graph JSON")
    analyzer = resolve_tool(
        analyzer_exe,
        default_analyzer_names(),
        "Build analyzer.c first, or pass --analyzer-exe PATH.",
    )

    run_process([analyzer, paths.graph, *analyzer_args], ctx, stage="analyzer")
    if not ctx.dry_run:
        resolve_existing_file(paths.analysis, "Analyzer output")
    log("[+] Analysis saved: " + str(paths.analysis), ctx.verbose)
    log("", ctx.verbose)


def run_refiner(paths: PipelinePaths, ctx: RunContext, step: str) -> None:
    """Run refiner.py against analysis and graph JSON."""

    banner(f"[STEP {step}] Refining Analysis", ctx.verbose)
    divider(ctx.verbose)
    resolve_existing_file(paths.analysis, "Analysis JSON")
    resolve_existing_file(paths.graph, "Graph JSON")
    refiner = ensure_script(SCRIPT_DIR / "refiner.py", "refiner.py")

    run_process(
        [sys.executable, refiner, paths.analysis, paths.graph, "--output", paths.refined],
        ctx,
        stage="refiner",
    )
    if not ctx.dry_run:
        resolve_existing_file(paths.refined, "Refined output")
    log("[+] Refined JSON saved: " + str(paths.refined), ctx.verbose)
    log("", ctx.verbose)


def run_visualizer(paths: PipelinePaths, ctx: RunContext, step: str) -> None:
    """Run visualizer.py against refined JSON."""

    banner(f"[STEP {step}] Generating Interactive HTML Report", ctx.verbose)
    divider(ctx.verbose)
    resolve_existing_file(paths.refined, "Refined JSON")
    visualizer = ensure_script(SCRIPT_DIR / "visualizer.py", "visualizer.py")

    run_process(
        [sys.executable, visualizer, paths.refined, "--output", paths.report],
        ctx,
        stage="visualizer",
    )
    if not ctx.dry_run:
        resolve_existing_file(paths.report, "HTML report")
    log("[+] HTML report saved: " + str(paths.report), ctx.verbose)
    log("", ctx.verbose)


def run_analysis_chain(
    state_json: Path,
    output_dir: Optional[Path],
    analyzer_exe: Optional[str],
    analyzer_args: Sequence[str],
    ctx: RunContext,
    *,
    step_offset: int = 0,
) -> PipelinePaths:
    """Run graph builder, analyzer, refiner, and visualizer."""

    paths = PipelinePaths.from_state(state_json, output_dir)
    paths.output_dir.mkdir(parents=True, exist_ok=True)

    build_graph(paths, ctx, step=f"{step_offset + 1}/4" if step_offset == 0 else f"{step_offset + 1}/5")
    run_analyzer(paths, analyzer_exe, analyzer_args, ctx, step=f"{step_offset + 2}/4" if step_offset == 0 else f"{step_offset + 2}/5")
    run_refiner(paths, ctx, step=f"{step_offset + 3}/4" if step_offset == 0 else f"{step_offset + 3}/5")
    run_visualizer(paths, ctx, step=f"{step_offset + 4}/4" if step_offset == 0 else f"{step_offset + 4}/5")
    return paths


def open_report(path: Path, verbose: bool) -> None:
    """Open an HTML report with the platform default browser."""

    try:
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=False)
        else:
            subprocess.run(["xdg-open", str(path)], check=False)
        log("[+] Opened report: " + str(path), verbose)
    except Exception as exc:
        raise PipelineError(f"Failed to open report {path}: {exc}") from exc


def print_success_summary(title: str, paths: Optional[PipelinePaths], started: float, verbose: bool) -> None:
    """Print elapsed time and generated files."""

    banner(title, verbose)
    log("Elapsed: " + format_duration(time.perf_counter() - started), verbose)
    if paths:
        log("", verbose)
        log("Generated Files:", verbose)
        log(f"  State JSON:    {paths.state}", verbose)
        log(f"  Graph JSON:    {paths.graph}", verbose)
        log(f"  Analysis JSON: {paths.analysis}", verbose)
        log(f"  Refined JSON:  {paths.refined}", verbose)
        log(f"  HTML Report:   {paths.report}", verbose)
    log("", verbose)


def command_collect(args: argparse.Namespace, collector_args: Sequence[str]) -> int:
    """Run collector-only mode."""

    started = time.perf_counter()
    ctx = RunContext(verbose=args.verbose or not args.quiet, dry_run=args.dry_run)
    state_path = run_collector(args, collector_args, ctx)
    banner("COLLECT COMPLETE", ctx.verbose)
    log("Elapsed: " + format_duration(time.perf_counter() - started), ctx.verbose)
    log("State JSON: " + str(state_path), ctx.verbose)
    return 0


def command_analyze(args: argparse.Namespace, analyzer_args: Sequence[str]) -> int:
    """Run graph builder, analyzer, refiner, and visualizer on an existing state JSON."""

    started = time.perf_counter()
    ctx = RunContext(verbose=args.verbose or not args.quiet, dry_run=args.dry_run)
    state = Path(args.state_json or DEFAULT_STATE_NAME)
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else None
    analyzer_options = build_analyzer_args(args, analyzer_args)

    banner("AD-AUTHGRAPH-V2 ANALYSIS", ctx.verbose)
    log("Input: " + str(state.expanduser().resolve()), ctx.verbose)
    if output_dir:
        log("Output directory: " + str(output_dir), ctx.verbose)
    log("", ctx.verbose)

    paths = run_analysis_chain(state, output_dir, args.analyzer_exe, analyzer_options, ctx)
    print_success_summary("ANALYSIS COMPLETE", paths, started, ctx.verbose)
    if args.open_report and not ctx.dry_run:
        open_report(paths.report, ctx.verbose)
    return 0


def command_pipeline(args: argparse.Namespace, collector_args: Sequence[str]) -> int:
    """Run the complete collector-to-report pipeline."""

    started = time.perf_counter()
    ctx = RunContext(verbose=args.verbose or not args.quiet, dry_run=args.dry_run)
    analyzer_options = build_analyzer_args(args, [])

    banner("AD-AUTHGRAPH-V2 FULL PIPELINE", ctx.verbose)
    state = run_collector(args, collector_args, ctx)
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else state.parent
    paths = run_analysis_chain(state, output_dir, args.analyzer_exe, analyzer_options, ctx, step_offset=1)
    print_success_summary("PIPELINE COMPLETE", paths, started, ctx.verbose)
    if args.open_report and not ctx.dry_run:
        open_report(paths.report, ctx.verbose)
    return 0


def looks_like_graph_json(path: Path) -> bool:
    """Return True for files already named like graph_builder output."""

    return path.stem.endswith("_graph")


def graph_path_for_compare(state: Path, output_dir: Path, suffix: str) -> PipelinePaths:
    """Create non-colliding derived paths for compare mode."""

    paths = PipelinePaths.from_state(state, output_dir)
    if paths.graph.exists() or suffix:
        stem = state.stem
        paths = PipelinePaths(
            state=paths.state,
            output_dir=paths.output_dir,
            graph=paths.output_dir / f"{stem}{suffix}_graph.json",
            analysis=paths.output_dir / f"{stem}{suffix}_analysis.json",
            refined=paths.output_dir / f"{stem}{suffix}_refined.json",
            report=paths.output_dir / f"{stem}{suffix}_report_refined.html",
        )
    return paths


def ensure_graph_for_compare(state_or_graph: Path, output_dir: Path, ctx: RunContext, suffix: str) -> Path:
    """Build a graph for a raw state snapshot, or reuse an existing graph JSON."""

    source = resolve_existing_file(state_or_graph, "Compare input")
    if looks_like_graph_json(source):
        return source

    paths = graph_path_for_compare(source, output_dir, suffix)
    build_graph(paths, ctx, step="compare")
    return paths.graph


def print_compare_summary(report: dict, verbose: bool) -> None:
    """Print the analyzer compare JSON in the old summary style."""

    current = report.get("current_state", {})
    previous = report.get("previous_state", {})
    delta = report.get("delta", {})
    changes = report.get("changes", {})

    banner("COMPARISON RESULTS", verbose)
    log("Current State:", verbose)
    log(f"  Domain Admin Paths: {current.get('da_paths', 0)}", verbose)
    log(f"  Total Edges:        {current.get('total_edges', 0)}", verbose)
    log(f"  Kerberoastable:     {current.get('kerberoastable', 0)}", verbose)
    log("", verbose)
    log("Previous State:", verbose)
    log(f"  Domain Admin Paths: {previous.get('da_paths', 0)}", verbose)
    log(f"  Total Edges:        {previous.get('total_edges', 0)}", verbose)
    log(f"  Kerberoastable:     {previous.get('kerberoastable', 0)}", verbose)
    log("", verbose)
    log("Deltas:", verbose)
    log(f"  DA Paths:       {delta.get('da_paths', 0):+d}", verbose)
    log(f"  Edges:          {delta.get('edges', 0):+d}", verbose)
    log(f"  Kerberoastable: {delta.get('kerberoastable', 0):+d}", verbose)

    new_da = changes.get("new_da_paths") or []
    removed_da = changes.get("removed_da_paths") or []
    new_kerb = changes.get("new_kerberoastable") or []
    if new_da:
        log(f"\nNew DA paths ({len(new_da)}):", verbose)
        for item in new_da[:20]:
            log(f"  + {item}", verbose)
    if removed_da:
        log(f"\nRemoved DA paths ({len(removed_da)}):", verbose)
        for item in removed_da[:20]:
            log(f"  - {item}", verbose)
    if new_kerb:
        log(f"\nNew Kerberoastable ({len(new_kerb)}):", verbose)
        for item in new_kerb[:20]:
            log(f"  + {item}", verbose)
    log("", verbose)


def command_compare(args: argparse.Namespace) -> int:
    """Run analyzer compare mode for two snapshots."""

    started = time.perf_counter()
    ctx = RunContext(verbose=args.verbose or not args.quiet, dry_run=args.dry_run)
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else Path(args.state1).expanduser().resolve().parent
    output_dir.mkdir(parents=True, exist_ok=True)

    banner("AUTHORIZATION STATE COMPARISON", ctx.verbose)
    log("Current:  " + str(Path(args.state1).expanduser().resolve()), ctx.verbose)
    log("Previous: " + str(Path(args.state2).expanduser().resolve()), ctx.verbose)
    log("Output:   " + str(output_dir), ctx.verbose)
    log("", ctx.verbose)

    graph1 = ensure_graph_for_compare(Path(args.state1), output_dir, ctx, "_current")
    graph2 = ensure_graph_for_compare(Path(args.state2), output_dir, ctx, "_previous")
    analyzer = resolve_tool(
        args.analyzer_exe,
        default_analyzer_names(),
        "Build analyzer.c first, or pass --analyzer-exe PATH.",
    )

    report_path = output_dir / f"{Path(args.state1).stem}_vs_{Path(args.state2).stem}_comparison.json"
    banner("[STEP compare] Running analyzer compare mode", ctx.verbose)
    divider(ctx.verbose)
    stdout = run_process([analyzer, graph1, "--compare", graph2], ctx, capture=True, stage="analyzer compare")

    if ctx.dry_run:
        return 0

    try:
        report = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raw_path = report_path.with_suffix(".raw.txt")
        raw_path.write_text(stdout, encoding="utf-8")
        raise PipelineError(f"Analyzer compare did not emit valid JSON; raw output saved to {raw_path}: {exc}") from exc

    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print_compare_summary(report, ctx.verbose)
    banner("COMPARE COMPLETE", ctx.verbose)
    log("Elapsed: " + format_duration(time.perf_counter() - started), ctx.verbose)
    log("Comparison report: " + str(report_path), ctx.verbose)
    return 0


def build_analyzer_args(args: argparse.Namespace, passthrough: Sequence[str]) -> List[str]:
    """Build analyzer flags from parsed options and extra arguments."""

    result: List[str] = []
    if getattr(args, "full", False):
        result.append("--full")
    authority_limit = getattr(args, "authority_sample_limit", None)
    if authority_limit is not None:
        result.extend(["--authority-sample-limit", str(authority_limit)])
    result.extend(passthrough)
    return result


def add_common_options(parser: argparse.ArgumentParser) -> None:
    """Add shared CLI options."""

    parser.add_argument("--output-dir", "-o", help="Directory for generated pipeline files.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show progress output (default).")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output.")
    parser.add_argument("--dry-run", action="store_true", help="Show commands without executing them.")


def add_analyzer_options(parser: argparse.ArgumentParser) -> None:
    """Add analyzer executable/options."""

    parser.add_argument("--analyzer-exe", help="Path to analyzer.exe/analyzer.")
    parser.add_argument("--full", action="store_true", help="Pass --full to analyzer.")
    parser.add_argument(
        "--authority-sample-limit",
        type=int,
        help="Pass --authority-sample-limit N to analyzer compact mode.",
    )


def add_collector_options(parser: argparse.ArgumentParser) -> None:
    """Add collector executable/options."""

    parser.add_argument("--collector-exe", help="Path to ADAuthCollector.exe/Program.exe.")
    parser.add_argument("--state-json", "--state", help="State JSON path to produce or consume.")


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""

    parser = argparse.ArgumentParser(
        description="AD-AuthGraph-v2 pipeline orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py collect --host dc01 --base-dn DC=corp,DC=local
  python main.py analyze ad_authorization_state.json --output-dir reports
  python main.py pipeline --host dc01 --base-dn DC=corp,DC=local --threads 8
  python main.py compare state1.json state2.json --output-dir reports

Collector arguments unknown to main.py are forwarded to the C# collector.
Analyzer output is produced by analyzer.exe/analyzer, not Python analyzer code.
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="Run only the C# collector.")
    add_common_options(collect)
    add_collector_options(collect)

    analyze = sub.add_parser("analyze", help="Run graph builder + analyzer + refiner + visualizer.")
    add_common_options(analyze)
    add_analyzer_options(analyze)
    analyze.add_argument("state_json", nargs="?", help=f"State JSON to analyze. Default: {DEFAULT_STATE_NAME}")
    analyze.add_argument("--open-report", action="store_true", help="Open the HTML report after completion.")

    pipeline = sub.add_parser("pipeline", help="Run the complete collector-to-report pipeline.")
    add_common_options(pipeline)
    add_collector_options(pipeline)
    add_analyzer_options(pipeline)
    pipeline.add_argument("--open-report", action="store_true", help="Open the HTML report after completion.")

    compare = sub.add_parser("compare", help="Compare two snapshots using analyzer compare mode.")
    add_common_options(compare)
    compare.add_argument("state1", help="Current state JSON or graph JSON.")
    compare.add_argument("state2", help="Previous state JSON or graph JSON.")
    compare.add_argument("--analyzer-exe", help="Path to analyzer.exe/analyzer.")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point."""

    parser = build_parser()
    args, unknown = parser.parse_known_args(argv)

    try:
        if args.command == "collect":
            return command_collect(args, unknown)
        if args.command == "analyze":
            return command_analyze(args, unknown)
        if args.command == "pipeline":
            return command_pipeline(args, unknown)
        if args.command == "compare":
            if unknown:
                raise PipelineError("compare does not accept extra arguments: " + " ".join(unknown))
            return command_compare(args)
        raise PipelineError("unknown command: " + args.command)
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user.")
        return 130
    except PipelineError as exc:
        print("[-] " + str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print("[-] Unexpected error: " + str(exc), file=sys.stderr)
        if "--debug" in sys.argv:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
