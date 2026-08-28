# MAIN.PY(1)

## NAME

**main.py** — AD-AuthGraph-v2 pipeline orchestrator

## SYNOPSIS

```
python main.py collect   [options] [-- collector-args...]
python main.py analyze   [state_json] [options] [-- analyzer-args...]
python main.py pipeline  [options] [-- collector-args...]
python main.py compare   <state1> <state2> [options]
python main.py -h | --help
```

## DESCRIPTION

**main.py** is the single entry point that drives the full AD-AuthGraph-v2 workflow end to end:

```
C# collector -> graph_builder.py -> analyzer(.exe) -> refiner.py -> visualizer.py
```

It does not reimplement any stage's logic. The collector and analyzer are invoked as **external executables** (resolved on disk or `PATH`); `graph_builder.py` is used **in-process** via a direct Python import of `AuthorizationGraph` (so output-directory naming stays deterministic without needing to copy enterprise-size state JSON files around); `refiner.py` and `visualizer.py` are invoked as **subprocesses** of the current Python interpreter (`sys.executable`).

Four subcommands are provided: `collect` (collector only), `analyze` (graph builder → analyzer → refiner → visualizer, on an existing state JSON), `pipeline` (collector, then everything `analyze` does), and `compare` (diff two snapshots via the analyzer's `--compare` mode).

## REQUIREMENTS

* Python 3.x (standard library only for `main.py` itself: `argparse`, `json`, `subprocess`, `dataclasses`, `pathlib`, etc.)
* A built collector executable (see `collect-adauth`(1) BUILD/COMPILATION) reachable by name or via `--collector-exe`.
* A built `analyzer`/`analyzer.exe` (see `analyzer`(1) BUILD/COMPILATION) reachable by name or via `--analyzer-exe`.
* `graph_builder.py`, `refiner.py`, `visualizer.py` present alongside `main.py` (same directory, `SCRIPT_DIR`).

## GLOBAL OPTIONS

Available on every subcommand:

`--output-dir DIR`, `-o DIR`
: Directory for all generated pipeline files. Defaults vary by subcommand (see below).

`--verbose`, `-v`
: Show progress output. This is effectively the default; see VERBOSITY.

`--quiet`, `-q`
: Suppress progress output (banners, step logs, subprocess command echoing). Errors are still printed.

`--dry-run`
: Print each command that *would* run (prefixed `$`) without executing it, and without touching the filesystem beyond directory creation. Useful for previewing exactly what a `pipeline`/`analyze`/`compare` invocation will do.

### VERBOSITY

Verbosity is computed as `args.verbose or not args.quiet` — i.e. output is verbose by default; `--quiet` suppresses it; `--verbose` forces it back on even if `--quiet` were also (redundantly) given. There is no fully-silent mode that also suppresses error output.

## SUBCOMMANDS

### `collect`

```
python main.py collect [--output-dir DIR] [--collector-exe PATH] [--state-json PATH] [common opts] [-- collector-args...]
```

Runs only the C# collector. Any arguments `main.py` doesn't recognize are forwarded verbatim to the collector executable (see COLLECTOR ARGUMENT FORWARDING).

`--collector-exe PATH`
: Explicit path (or `PATH`-resolvable name) to the collector executable. If omitted, `main.py` searches, in order: a local file named `ADAuthCollector.exe`/`Program.exe`/`collect-adauth-csharp.exe` (POSIX: without the `.exe` suffix) next to `main.py`, then the same names on `PATH`.

`--state-json PATH`, `--state PATH`
: Where the resulting authorization-state JSON should be written/expected. Ignored if the forwarded collector arguments already include `--output`/`--output-path`/`--output-file`. Default: `<output-dir>/ad_authorization_state.json`.

### `analyze`

```
python main.py analyze [state_json] [--output-dir DIR] [--analyzer-exe PATH] [--full] [--authority-sample-limit N] [--open-report] [common opts] [-- analyzer-args...]
```

Runs `graph_builder.py` → `analyzer` → `refiner.py` → `visualizer.py` against an **existing** authorization-state JSON (does not run the collector).

`state_json` (positional, optional)
: Path to the state JSON to analyze. Default: `ad_authorization_state.json` in the current directory.

`--open-report`
: After completion, open the generated HTML report with the platform default handler (`os.startfile` on Windows, `open` on macOS, `xdg-open` elsewhere).

`--analyzer-exe`, `--full`, `--authority-sample-limit N`
: Forwarded to the analyzer invocation; see `analyzer`(1) for their meaning. Unrecognized extra arguments are also forwarded to the analyzer.

### `pipeline`

```
python main.py pipeline [--output-dir DIR] [--collector-exe PATH] [--state-json PATH] [--analyzer-exe PATH] [--full] [--authority-sample-limit N] [--open-report] [common opts] [-- collector-args...]
```

Runs the **complete** collector-to-report pipeline: collector, then the same four stages as `analyze`. Accepts the union of `collect`'s and `analyze`'s collector/analyzer options, plus `--open-report`. Unrecognized arguments are forwarded to the collector (not the analyzer) in this subcommand.

### `compare`

```
python main.py compare <state1> <state2> [--output-dir DIR] [--analyzer-exe PATH] [common opts]
```

Compares two point-in-time snapshots using the analyzer's `--compare` mode (see `analyzer`(1) COMPARISON MODE). `state1`/`state2` may each be either a raw authorization-state JSON (in which case `main.py` builds a graph from it first, writing `<stem>_current_graph.json` / `<stem>_previous_graph.json` into the output directory) or an already-built `*_graph.json` file (detected purely by filename — any file whose stem ends in `_graph` is treated as already-built and used as-is, without re-validating its contents). This subcommand does **not** accept unrecognized/extra arguments — any are treated as a hard error.

Output: `<output-dir>/<state1_stem>_vs_<state2_stem>_comparison.json`, plus a human-readable delta summary (new/removed DA paths, new Kerberoastable identities, edge/DA-path/Kerberoastable count deltas) printed to stdout. If the analyzer's stdout is not valid JSON, the raw output is saved alongside the intended report path with a `.raw.txt` suffix and the failure is reported with that path for debugging.

## OUTPUT FILE NAMING

For a state JSON named `<stem>.json`, `analyze`/`pipeline` derive (in `--output-dir`, or the state file's own directory if unset):

```
<stem>_graph.json
<stem>_analysis.json
<stem>_refined.json
<stem>_report_refined.html
```

## COLLECTOR ARGUMENT FORWARDING

For `collect` and `pipeline`, any command-line token `main.py` doesn't recognize as one of its own options is passed through unchanged to the collector executable (e.g. `--host`, `--base-dn`, `--page-size`, `--threads`, etc. — see `collect-adauth`(1)). `main.py` inspects the forwarded arguments only to detect an existing `--output`/`--output-path`/`--output-file`; if none is present, it injects `--output <state_json_path>` itself so the resulting state file lands at the path `main.py` expects for the next stage.

For `analyze`, unrecognized arguments are instead forwarded to the **analyzer**, not the collector (there is no collector stage in `analyze`).

## PROCESS EXECUTION MODEL

Each subprocess invocation is logged as `    $ <command>` when verbose. Non-zero exit from any stage raises an internal `PipelineError` including the failed stage name, exit code, and captured stdout/stderr, which `main.py` prints and turns into a process exit code of `1` — a failure in any stage halts the pipeline; later stages are not attempted.

`--dry-run` short-circuits every `run_process()` call immediately after logging the command, before any subprocess is actually spawned, and before any stage-specific output-file existence check runs — so a dry run of `pipeline`/`analyze`/`compare` will not fail just because upstream files don't exist yet.

## EXIT STATUS

`0`
: Successful completion of the requested subcommand.

`1`
: A `PipelineError` occurred (missing tool/script, missing input file, non-zero subprocess exit, invalid analyzer-compare JSON output, etc.), or an unexpected exception occurred.

`130`
: Interrupted by the user (Ctrl-C / `KeyboardInterrupt`).

## HIDDEN DEBUG FLAG

If an unhandled, non-`PipelineError` exception occurs, `main.py` normally prints `[-] Unexpected error: ...` and exits `1`. If the literal token `--debug` appears anywhere in `sys.argv`, the exception is re-raised instead, producing a full Python traceback. This is checked directly against `sys.argv` rather than registered as an `argparse` option, so it is not shown in `--help` output and can be combined with any subcommand.

## EXAMPLES

Run the collector only, forwarding collector-specific flags:
```
python main.py collect --host dc01 --base-dn DC=corp,DC=local
```

Analyze an already-collected state file, writing outputs into `reports/`:
```
python main.py analyze ad_authorization_state.json --output-dir reports
```

Full end-to-end run against a live domain, with a wider analyzer authority sample and auto-opening the report:
```
python main.py pipeline --host dc01 --base-dn DC=corp,DC=local --authority-sample-limit 100 --open-report
```

Realistic full pipeline run where the collector lives in its own published directory (as `dotnet publish` produces it — see `collect-adauth`(1) BUILD/COMPILATION) rather than next to `main.py`:
```
python main.py pipeline --collector-exe ".\AD-AuthCollector\ADAuthCollector.exe" --host Blues-DC --base-dn "DC=blues,DC=local"
```

Preview a full pipeline run without executing anything:
```
python main.py pipeline --host dc01 --dry-run
```

Compare two prior collection snapshots:
```
python main.py compare state1.json state2.json --output-dir reports
```

Compare using already-built graph JSON files directly (skips graph-build steps):
```
python main.py compare state1_graph.json state2_graph.json
```

## NOTES / LIMITATIONS

* **In practice, `--collector-exe` is usually required, not optional.** The collector is typically a self-contained `dotnet publish` output — a directory containing `ADAuthCollector.exe` alongside its runtime DLLs and dependencies (see `collect-adauth`(1) BUILD/COMPILATION) — rather than a single standalone binary sitting next to `main.py` or registered on `PATH`. Auto-discovery (searching `SCRIPT_DIR` and `PATH` for `ADAuthCollector.exe`/`Program.exe`/`collect-adauth-csharp.exe`) will usually fail against a real deployment; expect to pass `--collector-exe` pointing at the collector's own publish directory, e.g. `--collector-exe ".\AD-AuthCollector\ADAuthCollector.exe"`.
* Collector executable name search includes `collect-adauth-csharp[.exe]` alongside `ADAuthCollector[.exe]`/`Program[.exe]` — reflecting the historical/help-banner name of the collector documented in `collect-adauth`(1); the actual build output from `dotnet publish` is `ADAuthCollector.exe`, which is tried first.
* `compare`'s detection of "already a graph JSON" is filename-based only (`stem.endswith("_graph")`) — a file that happens to match this naming pattern but isn't actually `graph_builder.py` output will be passed straight to the analyzer and fail there rather than being caught early by `main.py`.
* `graph_builder.py` is imported directly into the `main.py` process (not run as a subprocess), so any exception it raises during `analyze`/`pipeline`/`compare` is caught and wrapped as a `PipelineError` at the import/call site — behaviorally consistent with the other stages' failure handling, but architecturally different (in-process vs. subprocess) from how `refiner.py`, `visualizer.py`, the collector, and the analyzer are invoked.
* There is no way to skip individual stages within `analyze`/`pipeline` (e.g. "run graph builder and analyzer but skip refiner/visualizer") — the four-stage chain always runs as a unit once entered.

## SEE ALSO

`collect-adauth`(1), `graph_builder.py`(1), `analyzer`(1), `refiner.py`(1), `visualizer.py`(1), AD-AuthGraph-v2 USER_MANUAL.md
