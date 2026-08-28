# ANALYZER(1)

## NAME

**analyzer** — native C engine for high-performance analysis of AD-AuthGraph-v2 authorization graphs

## SYNOPSIS

```
analyzer <graph_json_file> [--full] [--authority-sample-limit N]
analyzer <graph_json_file> --compare <other_graph_json>
analyzer -h | --help
```

## DESCRIPTION

**analyzer** (source: `source/analyzer.c`) is the native C implementation of the Analyzer stage of the AD-AuthGraph-v2 pipeline, positioned after Graph Builder and before Refiner/Visualizer. It is a from-scratch, dependency-free reimplementation of a NetworkX-based Python analyzer, built for speed and bounded memory use on large graphs.

It consumes the graph JSON produced by `graph_builder.py` (via `export_graph_data()`) — **not** raw AD authorization state — and produces a structured analysis report identifying privilege-escalation paths to Domain Admins, Kerberoastable accounts, abusable ACL permissions, and risky Kerberos delegation configurations.

Internally, the graph is loaded into a compact integer-indexed representation (interned node IDs, CSR/compressed-sparse-row adjacency for both forward and reverse traversal) rather than a pointer-heavy graph structure, and reachability queries are answered using an SCC-condensed bitset cache (Kosaraju's algorithm to find strongly connected components, then group-reachability bitsets over the condensation) so that "can this identity reach group X" queries are close to O(1) after a one-time O(V+E) build, instead of a fresh traversal per query.

## BUILD / COMPILATION

`analyzer` is a single self-contained C11 source file with no third-party dependencies (only the C standard library). Build instructions are included as comments at the top of `analyzer.c`.

**Prerequisites**

* A C11-capable compiler: gcc/MinGW, clang, or MSVC (`cl`).
* Microsoft Visual C++ Build Tools if compiling with `cl` on Windows (also listed as a top-level project requirement).

**Linux/macOS/MinGW (gcc or clang)**
```
gcc -O3 -std=c11 -Wall -Wextra -o analyzer analyzer.c
```

**Windows (MSVC Developer Command Prompt)**
```
cl /O2 /std:c11 analyzer.c /Fe:analyzer.exe
```

No linker flags or external libraries are required in either case — everything used (`ctype.h`, `stdint.h`, `stdio.h`, `stdlib.h`, `string.h`, etc.) is part of the standard library.

The resulting binary is invoked as `analyzer` (POSIX) or `analyzer.exe` (Windows); examples below use `analyzer.exe` to match the source's own usage banner, but either build target behaves identically.

## USAGE

```
analyzer.exe <graph_json_file> [--full] [--authority-sample-limit N]
```
Run a full analysis of a single graph and write a report.

```
analyzer.exe <graph_json_file> --compare <other_graph_json>
```
Compare two previously-built graphs (e.g. successive collection snapshots) and print a JSON delta to stdout.

```
analyzer.exe -h
analyzer.exe --help
```
Print usage information and exit 0. Running with no arguments prints the same usage information and exits 1.

## OPTIONS

`--full`
: Emit an exhaustive legacy-style report: authority lists (which groups/DA-equivalent privileges an identity can reach, and what authorities an ACL abuse target grants) are fully materialized rather than sampled. Can produce very large output JSON on dense graphs; use only when full completeness is needed (e.g. deep manual review), not for routine refiner/visualizer input.

`--authority-sample-limit N`
: In the default (compact) output mode, caps the number of entries listed in each authority/`authorities_gained` array to `N` (must be a positive integer). Exact totals and a `*_truncated` boolean are still reported alongside the sample, so counts are never lost — only the enumerated list is capped. Default: `25`. Ignored when `--full` is given.

`--compare <other_graph_json>`
: Switches to comparison mode (see COMPARISON MODE below) instead of producing a full analysis report.

`--raw`
: Recognized but explicitly rejected: the C engine only accepts `graph_builder.py` output, not raw AD authorization-state JSON. If passed, the program prints an error directing you to run `graph_builder.py` first and exits 1.

## ANALYSIS PERFORMED

All analyses are anchored on the node with ID `Group:Domain Admins` (constant `DA_NODE_ID`); if this node is absent from the input graph, Domain-Admin-path-dependent analyses are simply empty rather than erroring.

**Domain Admin paths** (`domain_admin_paths`)
: For every identity with a path to Domain Admins, a reverse-BFS-derived shortest path plus up to a bounded number of additional example paths (bounded-depth/bounded-step-budget DFS, capped by `DEFAULT_MAX_PATH_LENGTH`, `MAX_EXAMPLE_PATHS`, and a global DFS step budget to guarantee termination on dense/cyclic graphs) is reported, along with a route count (capped at `ROUTE_COUNT_CAP`) and shortest path length.

**Kerberoastable identities** (`kerberoastable_analysis`)
: Every user/computer with a `has_spn` edge. Risk is `CRITICAL` if the identity has any path to Domain Admins, `HIGH` if it doesn't but reaches some other admin-equivalent authority, otherwise `MEDIUM`. Each entry lists its SPNs, path count/length to DA, and its reachable authority set (subject to sampling — see `--authority-sample-limit`).

**ACL abuse chains** (`acl_abuse_chains`)
: For every edge carrying a "dangerous" raw permission (`GenericAll`, `WriteDacl`, `WriteOwner`, `GenericWrite`, `WriteProperty`, `ExtendedRight`, `ResetPassword`, or `ForceChangePassword` appearing anywhere in the permission string) whose target has a bounded-length path to Domain Admins, a chain is recorded from the ACL-holder through to DA. Risk is `CRITICAL` if the target itself has group-membership-mediated reach to DA, `HIGH` if the ACL is the only path (no pre-existing group-membership path), or `MEDIUM` if the ACL merely offers a *shorter* path to DA than an existing group-membership path already provides.

**Delegation risks** (`delegation_risks`, folded into the report but summarized in `summary.delegation_risks`)
: Every edge whose `edge_type` contains "delegation" (case-insensitive). Risk is `CRITICAL` if the delegation is unconstrained **and** the delegating identity already holds admin-equivalent authority elsewhere, otherwise `MEDIUM`.

**Privilege distribution**
: A per-group count of how many user/computer identities can reach that group, computed once from the SCC-condensed reachability bitsets and used to populate summary/report statistics.

## COMPARISON MODE (`--compare`)

When `--compare <other_graph_json>` is given, `analyzer` loads and finalizes both graphs, computes Domain-Admin reachability and Kerberoastable sets for each, and diffs their edge sets (via an open-addressed pair-hash set keyed on `(source, target)`), printing a single JSON object to **stdout** (not a file) with `current_state`, `previous_state`, `changes` (new/removed DA-reachable identities, new/removed edge counts, newly-Kerberoastable identities), and a `delta` block of signed integer differences. This is intended for tracking authorization drift between two point-in-time collections of the same environment.

## OUTPUT

Standalone analysis mode writes a JSON report file, derived from the input filename: if the input contains `_graph.json`, that substring is replaced with `_analysis.json` (e.g. `state_5_graph.json` → `state_5_analysis.json`); otherwise `_analysis.json` is simply appended. The report is also summarized as human-readable text to stdout.

Top-level report keys: `metadata` (passed through from the input graph), `analysis_output_mode` (`"full"` or `"compact_refiner"`), `summary` (totals: identities, DA-reachable identities/paths, Kerberoastable count, ACL abuse target count, delegation risk count, output mode, sample limit), `domain_admin_paths`, `kerberoastable_analysis`, `acl_abuse_chains`, and delegation-risk detail.

Compare mode prints its JSON object directly to stdout instead of writing a file.

## EXIT STATUS

`0`
: Successful analysis, comparison, or `--help`.

`1`
: No arguments given; failed to load/parse the input graph JSON (or comparison graph); invalid or missing value for `--authority-sample-limit` or `--compare`; `--raw` was passed.

## EXAMPLES

Analyze a graph with default (refiner-safe, sampled) output:
```
analyzer.exe state_5_graph.json
```

Full, unsampled export for manual deep-dive review:
```
analyzer.exe state_5_graph.json --full
```

Widen the authority sample size without going fully exhaustive:
```
analyzer.exe state_5_graph.json --authority-sample-limit 100
```

Compare two collection snapshots to see what changed:
```
analyzer.exe state_6_graph.json --compare state_5_graph.json
```

## NOTES / LIMITATIONS

* Input **must** be `graph_builder.py` output (node/edge JSON), not raw collector authorization-state JSON; `--raw` is explicitly refused rather than silently misparsed.
* All Domain-Admin-anchored analyses depend on a node with ID exactly `Group:Domain Admins` existing in the input graph; environments with a renamed/localized Domain Admins group, or graphs that don't include it, will show empty DA-path results without a separate warning.
* Path enumeration (example paths, abuse chains) is intentionally bounded (`DEFAULT_MAX_PATH_LENGTH`, `DEFAULT_DFS_STEP_BUDGET`, `ROUTE_COUNT_CAP`, `MAX_EXAMPLE_PATHS`) to guarantee termination and bounded runtime/memory on dense or highly cyclic graphs; this means path/route counts are a lower bound on true path counts in extreme cases, not an exhaustive enumeration, even before `--authority-sample-limit` sampling is applied on top.
* Compact (default) output mode samples authority lists but always reports exact counts and a truncation flag, so downstream consumers can distinguish "sampled" from "complete" data — treat `--full` output as the only exhaustive source of truth for authority membership.

## SEE ALSO

`graph_builder.py`(1), `refiner.py`(1), `visualizer.py`(1), AD-AuthGraph-v2 USER_MANUAL.md
