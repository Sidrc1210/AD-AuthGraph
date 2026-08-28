# REFINER.PY(1)

## NAME

**refiner.py** — High-Risk OU ACL Path Refiner: enrich analyzer findings with organizational-unit context and graph-derived privilege proximity

## SYNOPSIS

```
python refiner.py <analysis_json> [<graph_json>] [--output <path>]
python refiner.py -h | --help
```

## DESCRIPTION

**refiner.py** (v2) is the Graph Refiner stage of the AD-AuthGraph-v2 pipeline, positioned after Analyzer and before Visualizer. It takes the findings produced by the analyzer (`analyzer.c` / `analyzer.py`) — Domain Admin paths, Kerberoastable identities, ACL abuse chains, delegation risks — and re-expresses each of them in terms of **where they sit in the OU tree** and **how graph-structurally close they are to Tier-0 privilege**, without re-running any graph traversal analysis itself.

Per its own docstring, the refiner's responsibilities are strictly:

1. Build a complete, graph-derived `IdentityRegistry` mapping node ID → DN → OU path.
2. Infer privilege proximity for every identity from graph structure (BFS distance to a Tier-0 anchor group), **not** from OU-name heuristics.
3. Map every analyzer finding to its OU ACL path context.
4. Emit a heatmap of control-edge density per OU.
5. Keep **all** findings; annotate priority — filtering is left to the visualizer.

It explicitly does **not**: re-run graph analysis, make risk decisions based on OU naming conventions, or drop findings.

## REQUIREMENTS

* Python 3.x (standard library only — no third-party packages required by this module).

## USAGE

```
python refiner.py <analysis_json> [<graph_json>] [--output <path>]
```

`<analysis_json>` (required)
: Path to the analyzer's output JSON (e.g. `ad_authorization_state_analysis.json` / `<name>_analysis.json`).

`<graph_json>` (optional, recommended)
: Path to the graph builder's output JSON (e.g. `ad_authorization_state_graph.json` / `<name>_graph.json`). If omitted, the refiner auto-detects it by substituting `_analysis.json` → `_graph.json` in the analysis path. If neither is supplied nor found, the refiner proceeds without DN/OU/proximity enrichment (see DEGRADED MODE).

`--output <path>`
: Output path for the refined JSON. Default: `ad_authorization_state_refined.json`.

`-h`, `--help`
: Print usage and pipeline summary, exit 0.

Arguments are parsed positionally: the first non-flag argument is the analysis path, the second non-flag argument (if present) is the graph path, and `--output` takes the following token as its value. Order of `<graph_json>` and `--output` relative to each other does not matter.

## PIPELINE POSITION

```
graph_builder.py  -> ad_authorization_state_graph.json
analyzer (.c/.py) -> ad_authorization_state_analysis.json
refiner.py        -> ad_authorization_state_refined.json
visualizer.py      -> ad_authorization_state_report_refined.html
```

## HOW IT WORKS

### IdentityRegistry

A registry mapping every node ID to its DN, parsed OU path (`OU=` components only, DC components excluded, ordered leaf-first), node type, and SAM account name.

* **Primary source:** the graph JSON's `nodes` array — authoritative and (in principle) complete, since it should contain every AD object with a DN.
* **Overlay:** any node ID referenced by the analysis JSON (in DA paths, ACL abuse chain nodes, Kerberoastable entries, or delegation risk source/target) that is *not* already in the registry is added with an empty DN/OU path. This guarantees every node the analyzer talks about has *some* registry entry, even if the graph JSON is missing, stale, or incomplete relative to the analysis.
* Per-node OU label/path lookups are cached on first access.

### Privilege proximity (Tier-0 distance)

A fixed set of **Tier-0 anchor group SAM names** is hardcoded (`TIER0_GROUP_SAMS`): Domain Admins, Enterprise Admins, Schema Admins, Administrators, Group Policy Creator Owners, Account Operators, Backup Operators, Print Operators, Server Operators, Domain Controllers, Read-only Domain Controllers, DnsAdmins. Any group node whose SAM matches this list is marked a Tier-0 anchor.

A multi-source BFS is run over the graph's edges (reversed, so that predecessors of Tier-0 groups — e.g. members, ACL-holders — get proximity `1`, their predecessors `2`, and so on) to compute, for every node, its minimum hop distance to *any* Tier-0 anchor. `proximity == 0` means the node itself is a Tier-0 group; `None` means no path to Tier-0 was found in the loaded graph.

**Direction fallback:** if reverse-edge BFS covers less than 5% of loaded nodes (a signal that edge direction in the input graph may not match the assumed escalation direction, or the graph is otherwise degenerate), the refiner retries using forward edges and keeps whichever direction covers more nodes, logging which one was used.

This computation is purely graph-structural — it deliberately does not use OU names, group names outside the Tier-0 list, or any heuristic naming convention.

### Finding refinement passes

Four independent passes, each consuming the corresponding analyzer output section and enriching every entry with `node_context()` (SAM, node type, DN, OU path, OU label, privilege proximity, `is_tier0` flag) for the relevant node(s):

* **ACL abuse** (`high_risk_ou_acl_paths`) — from `acl_abuse_chains`. Adds source/target OU context, an `acl_path_direction` label (`OU-of-source -> OU-of-target`), the full escalation chain with per-step OU trajectory, and carries forward `authorities_gained`/`_count`/`_truncated` from the analyzer without re-interpreting them. Sorted by source privilege proximity (closest to Tier-0 first), then chain length.
* **Domain Admin paths** (`da_path_ou_map`) — from `domain_admin_paths`. Adds OU trajectory for the shortest path, and a `proximity_analysis_agreement` flag: `False` if the analyzer found a DA path but the refiner's own graph-BFS proximity computation did not find one for that node — a signal of a possible edge-coverage gap between the analyzer's graph and the graph JSON given to the refiner. Sorted by proximity, then path length.
* **Kerberoastable identities** (`kerberoastable_ou_map`) — from `kerberoastable_analysis`. Adds OU context and privilege proximity per identity. (v1's OU-name-based risk elevation heuristic has been removed in this version; proximity now does that job.) Sorted by proximity, then shortest path length.
* **Delegation risks** (`delegation_ou_map`) — from `delegation_risks`. Adds OU context for both source and target and an `acl_path_direction` label. Sorted by source proximity.

All four passes preserve every finding from the analyzer input — none are dropped.

### OU risk heatmap

After all four passes run (so control-edge density from the ACL pass is fully populated), `_build_ou_risk_heatmap()` aggregates, per distinct OU path label, across every finding type: total finding count, control-edge count (dangerous ACL edges originating from that OU), count of unique ACL targets influenced, whether any identity in that OU has a Tier-0 path, the minimum privilege proximity of any identity there, and the sorted set of involved SAMs. Heatmap entries are sorted with DA-reachable OUs first, then by ascending minimum proximity, then by descending control-edge count.

## OUTPUT

A single JSON file (default `ad_authorization_state_refined.json`) with top-level keys:

```
{
  "metadata": { ...analyzer metadata..., "refined_at": "...", "refiner_version": "2.0.0" },
  "summary": { domain, collection_date, refined_at, total_identities_in_analysis,
               registry_size, total_acl_findings, identities_with_da_paths,
               kerberoastable_identities, delegation_risks },
  "high_risk_ou_acl_paths": [ ... ],
  "da_path_ou_map":         [ ... ],
  "kerberoastable_ou_map":  [ ... ],
  "delegation_ou_map":      [ ... ],
  "ou_risk_heatmap":        [ ... ]
}
```

Written with `utf-8-sig` encoding. A human-readable refinement summary (domain, registry size, finding counts) is also printed to stdout.

## DEGRADED MODE (no graph JSON)

If no graph JSON is supplied and none is auto-detected beside the analysis file, the refiner still runs, using only the analysis-overlay registry entries. In this mode:

* `privilege_proximity` is `None` for every node (no BFS is possible without graph edges), so `is_tier0` is always `False` and proximity-based sorting effectively falls back to its `9999` default for all entries.
* DN and OU path are empty for every node, so OU labels degrade to `"(Domain Root)"` (or just the domain prefix) for everything, and the OU heatmap collapses toward a single bucket.

Supplying the matching graph JSON is strongly recommended; without it, the refiner's core value (OU/proximity context) is largely lost even though it will not error out.

## EXIT STATUS

`0`
: Successful refinement, or `--help`.

`1`
: `<analysis_json>` does not exist, or an unhandled exception occurred during refinement (registry build, JSON parse, or any refinement pass). A traceback is printed to stdout/stderr in the latter case.

## EXAMPLES

Auto-detect the graph JSON beside the analysis file:
```
python refiner.py state_5_analysis.json
```

Explicit graph JSON and custom output path:
```
python refiner.py state_5_analysis.json state_5_graph.json --output state_5_refined.json
```

Analysis-only run (no graph JSON available):
```
python refiner.py state_5_analysis.json --output state_5_refined.json
```

## NOTES / LIMITATIONS

* **Exploitability scoring has been removed; the docstring is stale.** The module docstring and several method docstrings still describe attaching "exploitability scores" to ACL abuse chains and setting a per-finding `priority_flag` for the visualizer. That scoring logic (and the ACL-right weighting table stubbed out in a comment near the top of the file) has been removed from this version — no `exploitability` field and no `priority_flag` key are set on any finding. Findings are still fully enriched with OU/proximity context and sorted by proximity; treat sort order as the current proxy for priority. If exploitability scoring is reintroduced later, the docstrings/comments referencing it should be updated (or removed) to match.
* The Tier-0 anchor list (`TIER0_GROUP_SAMS`) is a fixed, hardcoded set of well-known built-in group names. Environments that have renamed these groups, or that consider additional custom groups Tier-0-equivalent, will need to edit this constant — there is no CLI option to extend it.
* `proximity_analysis_agreement == False` in `da_path_ou_map` is a useful data-quality signal (analyzer found a DA path the refiner's own BFS didn't) but the refiner does not attempt to reconcile or explain the discrepancy beyond flagging it.
* The refiner reads whatever `analysis_json` and `graph_json` you point it at — it does not verify they come from the same collection run. Pairing mismatched snapshots will silently produce a refined file with inconsistent proximity/finding correlation rather than an error.

## SEE ALSO

`graph_builder.py`(1), `analyzer`(1), `visualizer.py`(1), AD-AuthGraph-v2 USER_MANUAL.md
