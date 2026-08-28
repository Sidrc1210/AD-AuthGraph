# GRAPH_BUILDER.PY(1)

## NAME

**graph_builder.py** — build a directed authorization graph from an AD-AuthGraph-v2 authorization state JSON file

## SYNOPSIS

```
python graph_builder.py <json_file>
```

## DESCRIPTION

**graph_builder.py** is the Graph Builder stage of the AD-AuthGraph-v2 pipeline. It consumes the authorization-state JSON produced by a collector (`collect-adauth`/`ADAuthCollector.exe` or `Collect-ADAuthorization.ps1`) and models it as a directed graph using NetworkX, where **nodes** represent identities (users, groups, computers, SPNs) and **edges** represent directory-mediated authority relationships (group membership, ACL permissions, SPN ownership, Kerberos delegation).

The module is built around the `AuthorizationGraph` class, which can also be imported and driven programmatically by downstream stages (`refiner.py`, `analyzer.c` via its own I/O, `visualizer.py`) rather than only run standalone via its `main()` CLI entry point. Running the file directly is intended as a smoke test / standalone conversion utility, invoking `AuthorizationGraph.load_from_json()` followed by `export_graph_data()`.

## REQUIREMENTS

* Python 3.x
* `networkx` (see `requirements.txt`)

## USAGE

```
python graph_builder.py <json_file>
```

`<json_file>`
: Path to an authorization state JSON file (see INPUT FORMAT). Required; the script exits with status 1 and prints usage if omitted.

There are no other command-line flags. All other behavior is exposed only via the `AuthorizationGraph` class API (see PYTHON API).

## INPUT FORMAT

The input JSON is expected to contain the following top-level keys (all optional except where downstream logic depends on them — missing keys default to empty lists/dicts):

* `metadata` — `{domain, collection_date, ...}`, echoed to stdout during load.
* `users` — each with `sam_account_name`, `distinguished_name`, `sid`, `enabled`, optional `description`, `has_delegation`.
* `groups` — each with `sam_account_name`, `distinguished_name`, `sid`, optional `description`, `group_category`, `group_scope`.
* `computers` — each with `sam_account_name`, `distinguished_name`, `sid`, `enabled`, optional `operating_system`, `trusted_for_delegation`.
* `spns` — each with `spn`, `identity_type` (`user`/`computer`), `identity_sam`, optional `enabled`.
* `group_memberships` — each with `member_type` (`user`/`computer`/`group`), `member_sam`, `group_sam`, `direct_membership`.
* `delegation` — each with `identity_type`, `identity_sam`, `delegation_type` (`unconstrained`/`constrained`/`constrained_with_protocol_transition`), optional `allowed_targets`.
* `acl_permissions` — each with `target_type` (`user`/`group`), `target_sam`, `trustee_identity`, `permission`, optional `object_type_guid`, `access_control_type`.
* `collection_issues` *(optional, newer collector output only)* — a list of records describing objects the collector could not fully enumerate (e.g. `ACCESS_DENIED`, `ENUMERATION_BLOCKED`, `UNAVAILABLE`), each with at least a `status` field. Absent in output from older collector builds; the graph builder treats this as an empty list with no change in behavior.

The `trustee_identity` field on ACL entries is accepted in either of two formats and resolved against already-loaded nodes:
* Legacy `type:sam` form, e.g. `user:jsmith`
* PowerShell-collector `DOMAIN\username` (or `DOMAIN/username`) form, e.g. `CORP\jsmith`

Trustees that cannot be resolved to a known user/group/computer node (e.g. `NT AUTHORITY\SYSTEM`, `Everyone`, and other well-known/system principals) are silently skipped rather than added as edges.

## GRAPH MODEL

**Node types:** `user`, `group`, `computer`, `spn`, and a synthetic `wildcard` node (`Identity:*`) used as the sink for unconstrained-delegation edges. Node IDs are of the form `User:<sam>`, `Group:<sam>`, `Computer:<sam>`, `SPN:<spn value>`.

**Edge types produced:**

| edge_type | Source → Target | Meaning |
|---|---|---|
| `member_of` | identity → group | Direct or nested group membership (`direct_membership` flag preserved) |
| `has_spn` | user/computer → SPN | Identity has a registered SPN (Kerberoastable) |
| `trusted_for_delegation` | user/computer → `Identity:*` | Unconstrained delegation — can impersonate any authenticating identity |
| `constrained_delegation` | user/computer → SPN | Constrained (optionally protocol-transition) delegation to a specific target SPN |
| `has_GenericAll_on` / `has_WriteDACL_on` / `has_WriteOwner_on` / `has_GenericWrite_on` / `has_WriteProperty_on` / `has_ExtendedRight_on` / `has_permission_on` | trustee → user/group | Derived from the ACL `permission` string; the most specific matching right is used, falling back to `has_permission_on`. `ExtendedRight` edges additionally attempt to resolve `object_type_guid` to a human-readable right name via the built-in `EXTENDED_RIGHTS_MAP` (covers `ResetPassword`, `User-Change/Force-Change-Password`, `Send-As`, `DS-Replication-Get-Changes[-All]`; unknown GUIDs resolve to `None`). |

A formal **edge contract** dictionary (`AuthorizationGraph.edge_contracts`) documents, for a subset of edge families (`member_of`, `local_admin_on`, `has_permission_on`, `has_spn`, `trusted_for_delegation`), whether the relationship is conditional, how it is mediated/enforced, and what authority it grants. `local_admin_on` is defined in the contract but is **not currently emitted** by any edge-building method in this file — it is reserved for a data source not yet wired into this collector/builder pair.

Edges are only added when both endpoint nodes already exist in the graph (skipping dangling/unresolvable references) and, for ACL edges, when source and target are not the same node (no self-loops).

## COLLECTION ISSUES PASSTHROUGH

If the input JSON includes a `collection_issues` array (emitted by patched/newer collector builds when parts of the directory could not be enumerated, e.g. due to access denied), `graph_builder.py` carries it forward unchanged into `statistics.collection_issues` (a count) and a top-level `collection_issues` array in the exported graph JSON. A warning summarizing issue counts by status is printed to stdout at load time. This exists so that downstream stages (refiner, analyzer, visualizer) and their consumers can distinguish "zero findings because this part of the domain is clean" from "zero findings because the collector couldn't see this part of the domain" — the two are not equivalent and should not be treated as such when interpreting results.

## OUTPUT

Running as a script writes `<json_file_without_.json>_graph.json` (e.g. `state_5.json` → `state_5_graph.json`) via `export_graph_data()`, containing:

```
{
  "metadata": {...},
  "statistics": {...},
  "collection_issues": [...],
  "nodes": [ { "id": "...", "node_type": "...", ... }, ... ],
  "edges": [ { "source": "...", "target": "...", "edge_type": "...", ... }, ... ]
}
```

`statistics` includes `nodes`, `edges`, `users`, `groups`, `computers`, `spns`, and `collection_issues` counts, printed to stdout after a successful load and again (in full) after processing.

## PYTHON API

For use by other pipeline stages or custom scripts:

```python
from graph_builder import AuthorizationGraph

g = AuthorizationGraph()
if g.load_from_json("state_5.json"):
    graph = g.get_graph()                 # networkx.DiGraph
    stats = g.get_statistics()            # dict
    meta = g.get_metadata()               # dict
    issues = g.get_collection_issues()    # list[dict]
    node = g.get_node("User:jsmith")      # dict | None
    out_edges = g.get_edges_from("User:jsmith")
    in_edges = g.get_edges_to("Group:Domain Admins")
    g.export_graph_data("out_graph.json")
```

`AuthorizationGraph()`
: Construct an empty graph with zeroed statistics.

`load_from_json(filepath: str) -> bool`
: Load and build the graph from an authorization state JSON file. Returns `True` on success; returns `False` (and prints a diagnostic to stdout) on file-not-found, invalid JSON, or any other exception during load — it does not raise.

`get_graph() -> networkx.DiGraph`
: The underlying graph object, for direct NetworkX analysis.

`get_statistics() -> dict`, `get_metadata() -> dict`, `get_collection_issues() -> list[dict]`
: Accessors for the corresponding internal state.

`get_node(node_id: str) -> dict | None`
: Node attribute dict, or `None` if the node doesn't exist.

`get_edges_from(node_id: str) -> list[tuple]`, `get_edges_to(node_id: str) -> list[tuple]`
: Outgoing / incoming edges as `(source, target, attrs)` tuples.

`export_graph_data(output_file: str = "graph_data.json") -> bool`
: Serialize the graph to the JSON structure described in OUTPUT. Returns `True`/`False` in the same style as `load_from_json`.

## EXIT STATUS

`0`
: Successful standalone run.

`1`
: No input file argument supplied, or `load_from_json()` returned `False` (file not found, invalid JSON, or other load error).

## EXAMPLES

Build and export a graph from a collector output file:
```
python graph_builder.py state_5.json
```
produces `state_5_graph.json` in the same directory.

Programmatic use, e.g. from `refiner.py` or a notebook:
```python
from graph_builder import AuthorizationGraph
g = AuthorizationGraph()
g.load_from_json("state_5.json")
print(g.get_statistics())
```

## NOTES / LIMITATIONS

* `local_admin_on` is defined in `edge_contracts` but no data source in the current collector/builder pair populates it; this is a placeholder for a future local-admin-rights collection source (e.g. SAM/LSA enumeration or GPP data).
* ACL edge resolution silently drops trustees it cannot map to a known node (well-known SIDs/system principals such as `NT AUTHORITY\SYSTEM`, `Everyone`, `Authenticated Users`). This is intentional noise reduction, not an error condition.
* `collection_issues` is purely a passthrough/accounting field in this stage; `graph_builder.py` does not itself alter graph construction based on issue contents — it is the responsibility of downstream consumers (refiner, analyzer, visualizer, or the analyst) to treat affected regions of the graph as incomplete rather than confirmed-clean.
* File I/O uses `utf-8-sig` encoding on both read and write, to tolerate/produce a UTF-8 BOM as emitted by some PowerShell JSON output.

## SEE ALSO

`collect-adauth`(1), `Collect-ADAuthorization.ps1`(1), `refiner.py`(1), `analyzer.c`(1), `visualizer.py`(1), AD-AuthGraph-v2 USER_MANUAL.md
