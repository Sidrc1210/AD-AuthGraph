"""
refiner.py - High-Risk OU ACL Path Refiner  (v2)

Consumes:
    ad_authorization_state_graph.json    (graph_builder.py output)
    ad_authorization_state_analysis.json (analyzer.py output)

Produces:
    ad_authorization_state_refined.json  → feeds visualizer_2.py

Responsibilities (and ONLY these):
    1. Build a complete, graph-derived IdentityRegistry (DN → OU path).
    2. Infer privilege proximity for every identity from the graph structure,
       NOT from OU name heuristics.
    3. Attach exploitability scores to ACL abuse chains (attack-usefulness
       ranking, not just label propagation).
    4. Map every finding to its OU ACL path context.
    5. Emit a heatmap with control-edge density per OU.
    6. Keep ALL findings; mark priority flags — let visualizer filter.

This module does NOT:
    - Re-run any graph analysis (that is analyzer.py's job).
    - Make decisions based on OU naming conventions.
    - Drop findings silently (all findings are preserved; priority is annotated).

Author: Siddharth Ray Chaudhuri
Date: 2026-04-20 (v2 — full rewrite incorporating structural review feedback)
Purpose: Authorization Graph Modeling Project
"""

import json
import sys
from collections import defaultdict
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# ACL right exploitability weights
#
# These reflect the practical attack cost to exploit each right.
# Higher score = lower attack cost = more exploitable.
# These are attack-technique weights, not risk labels — they belong here
# in the refiner, not in the analyzer.
# ---------------------------------------------------------------------------

# (substring_to_match_in_permission, score)
# Evaluated in order; first match wins per right.

# Tier-0 group SAM names that anchor the privilege proximity graph.
# Used ONLY to compute graph-structural distance — NOT for OU classification.
TIER0_GROUP_SAMS: Set[str] = {
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Group Policy Creator Owners",
    "Account Operators",
    "Backup Operators",
    "Print Operators",
    "Server Operators",
    "Domain Controllers",
    "Read-only Domain Controllers",
    "DnsAdmins",
}

# ---------------------------------------------------------------------------
# Pure helper functions  (no class state needed)
# ---------------------------------------------------------------------------

def _extract_dn_ou_path(dn: str) -> List[str]:
    """
    Parse a Distinguished Name and return the ordered list of OU components,
    most-specific first (leaf -> root), DC components excluded.

    Example:
        "CN=jdoe,OU=Analysts,OU=Users,OU=Corp,DC=blues,DC=local"
        -> ["OU=Analysts", "OU=Users", "OU=Corp"]
    """
    if not dn:
        return []
    return [
        p.strip()
        for p in dn.split(",")
        if p.strip().upper().startswith("OU=")
    ]


def _ou_label(ou_components: List[str], domain: str = "") -> str:
    """
    Build a human-readable ACL path label from OU components.

    Components are reversed so the label reads root -> leaf:
        ["OU=Analysts", "OU=Users", "OU=Corp"]
        -> "blues.local // Corp -> Users -> Analysts"
    """
    readable = [
        c[3:] if c.upper().startswith("OU=") else c
        for c in reversed(ou_components)
    ]
    label = " -> ".join(readable) if readable else "(Domain Root)"
    return f"{domain} // {label}" if domain else label


def _sam_from_id(node_id: str) -> str:
    """'User:jdoe' -> 'jdoe',  'Group:Domain Admins' -> 'Domain Admins'"""
    return node_id.split(":", 1)[1] if ":" in node_id else node_id


def _type_from_id(node_id: str) -> str:
    """'User:jdoe' -> 'User'"""
    return node_id.split(":", 1)[0] if ":" in node_id else "Unknown"



# ---------------------------------------------------------------------------
# IdentityRegistry
#
# Primary source: graph JSON  (full population of all AD objects with DNs)
# Secondary overlay: analysis JSON  (adds node IDs not in graph if graph absent)
#
# Corrected load order per review feedback:
#   graph JSON first (authoritative, complete)
#   analysis JSON overlay second (gap-filler only)
# ---------------------------------------------------------------------------

class IdentityRegistry:
    """
    Maps node IDs to their structural AD context (DN, OU path, privilege
    proximity score).

    Graph JSON is the primary source. Analysis JSON is overlaid only to
    cover node IDs the graph did not include.

    All per-node OU lookups are cached on first access to eliminate
    repeated string operations at scale.
    """

    def __init__(self) -> None:
        # node_id -> { dn, ou_path, node_type, sam }
        self._store: Dict[str, Dict] = {}

        # Cached derived values: node_id -> { ou_label, ou_path }
        self._ou_cache: Dict[str, Dict] = {}

        # Tier-0 anchor node IDs (populated during graph load)
        self._tier0_node_ids: Set[str] = set()

        # privilege_proximity: node_id -> int (0 = IS Tier-0, higher = farther away)
        # None = no path to Tier-0 found in graph
        self._proximity: Dict[str, int] = {}
        self._proximity_computed: bool = False

        # Raw directed adjacency for BFS: node_id -> set of successor node_ids
        self._graph_edges: Dict[str, Set[str]] = defaultdict(set)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_from_graph(self, graph_data: Dict) -> int:
        """
        Primary load: populate registry from ALL nodes in graph JSON.
        This is the authoritative source — every AD object with a DN.

        Returns count of nodes loaded.
        """
        count = 0
        for node in graph_data.get("nodes", []):
            node_id = node.get("id", "")
            if not node_id:
                continue
            dn        = node.get("dn", "")
            node_type = node.get("node_type", _type_from_id(node_id))
            sam       = node.get("sam", _sam_from_id(node_id))
            ou_path   = _extract_dn_ou_path(dn)

            self._store[node_id] = {
                "node_id":   node_id,
                "node_type": node_type,
                "sam":       sam,
                "dn":        dn,
                "ou_path":   ou_path,
            }
            count += 1

            # Mark Tier-0 anchors by SAM match — no name heuristics beyond this list
            if str(node_type).lower() == "group" and sam in TIER0_GROUP_SAMS:
                self._tier0_node_ids.add(node_id)

        # Collect edges for BFS proximity computation
        for edge in graph_data.get("edges", []):
            src = edge.get("source", "")
            tgt = edge.get("target", "")
            if src and tgt:
                self._graph_edges[src].add(tgt)

        print(f"    [+] IdentityRegistry: {count} nodes loaded from graph JSON")
        print(f"    [+] Tier-0 anchors identified: {len(self._tier0_node_ids)}")
        return count

    def overlay_from_analysis(self, analysis: Dict) -> int:
        """
        Secondary overlay: register any node IDs referenced in the analysis
        that were NOT present in the graph JSON (handles graph-absent case).

        Returns count of NEW entries added (not updates to existing).
        """
        new_count = 0

        def _ensure(node_id: str) -> None:
            nonlocal new_count
            if not node_id or node_id in self._store:
                return
            self._store[node_id] = {
                "node_id":   node_id,
                "node_type": _type_from_id(node_id),
                "sam":       _sam_from_id(node_id),
                "dn":        "",
                "ou_path":   [],
            }
            new_count += 1

        for node_id, data in analysis.get("domain_admin_paths", {}).items():
            _ensure(node_id)
            for path in data.get("paths", []):
                for step in path:
                    _ensure(step)

        for target_id, chains in analysis.get("acl_abuse_chains", {}).items():
            _ensure(target_id)
            for chain in chains:
                _ensure(chain.get("source", ""))
                _ensure(chain.get("target", ""))
                for step in chain.get("abuse_chain", []):
                    _ensure(step)

        for node_id in analysis.get("kerberoastable_analysis", {}):
            _ensure(node_id)

        for risk in analysis.get("delegation_risks", []):
            _ensure(risk.get("source", ""))
            _ensure(risk.get("target", ""))

        if new_count:
            print(f"    [+] Analysis overlay: {new_count} node IDs added (absent from graph)")
        return new_count

    # ------------------------------------------------------------------
    # Privilege proximity — graph-derived, NOT name-derived
    # ------------------------------------------------------------------

    


    def compute_privilege_proximity(self) -> None:
        """
        Reverse BFS from ALL Tier-0 anchor nodes through the graph.

        proximity[node_id] = minimum hops from that node TO any Tier-0 group,
        travelling in the direction of privilege escalation.

        We invert edge direction so we can BFS outward FROM Tier-0 and reach
        all predecessor nodes (i.e. those that can reach Tier-0 forward).

        Results:
            proximity == 0   -> node IS a Tier-0 anchor
            proximity == 1   -> direct member of / direct control over Tier-0
            proximity == N   -> N-hop chain to Tier-0
            no entry         -> no path to Tier-0 in the graph
       """
        # Direction-safe BFS:
        # Try reverse edges (expected escalation direction)
        # If Tier-0 reachability is abnormally low, retry using forward edges
        # and select the direction with better coverage
        

        if self._proximity_computed:
            return
            
        # ---Build reverse adjacency ---
        reverse_adj: Dict[str, Set[str]] = defaultdict(set)
        for src, targets in self._graph_edges.items():
           for tgt in targets:
                reverse_adj[tgt].add(src)

      # --- Local BFS helper (must be inside method to use self) ---
        def _bfs(adj: Dict[str, Set[str]]) -> Dict[str, int]:
            prox: Dict[str, int] ={}
            queue: List[Tuple[str, int]] = []
            visited: Set[str] = set()

            for anchor in self._tier0_node_ids:
                prox[anchor] = 0
                queue.append((anchor, 0))
                visited.add(anchor)

            head = 0
            while head < len(queue):
               current, dist = queue[head]
               head += 1
               for nxt in adj.get(current, set()):
                   if nxt not in visited:
                      visited.add(nxt)
                      prox[nxt] = dist +1
                      queue.append((nxt, dist +1))

            return prox
            
        # --- Try reverse direction first ---
        prox_reverse = _bfs(reverse_adj)

        total_nodes = len(self._store)
        coverage_ratio = len(prox_reverse) / total_nodes if total_nodes else 0

        # --- Fallback if suspicious ---
        if coverage_ratio < 0.05:
           print("   [!] Low Tier-0 reachability detected - trying forward edge direction")
           prox_forward = _bfs(self._graph_edges)

           if len(prox_forward) > len(prox_reverse):
              self._proximity = prox_forward
              print(f"   [+] Using FORWARD edges: {len(prox_forward)} nodes reach Tier-0")
           else:
               self._proximity = prox_reverse
               print(f"   [+] Using REVERSE edges: {len(prox_reverse)} nodes reach Tier-0")
        else: 
            self._proximity = prox_reverse
            print(f"   [+] Using REVERSE edges: {len(prox_reverse)} nodes reach Tier 0")

        self._proximity_computed = True                  
                                        
            
    # ------------------------------------------------------------------
    # Public lookup API  (all OU data cached on first access)
    # ------------------------------------------------------------------

    def _cached_ou(self, node_id: str) -> Dict:
        """
        Build and cache OU context for a node_id.
        Called once per node; result reused on all subsequent lookups.
        """
        if node_id in self._ou_cache:
            return self._ou_cache[node_id]
        entry   = self._store.get(node_id, {})
        ou_path = entry.get("ou_path", [])
        result  = {
            "ou_path":  ou_path,
            "ou_label": _ou_label(ou_path),   # domain prefix added ad-hoc
        }
        self._ou_cache[node_id] = result
        return result

    def ou_path(self, node_id: str) -> List[str]:
        return self._cached_ou(node_id)["ou_path"]

    def ou_label(self, node_id: str, domain: str = "") -> str:
        base = self._cached_ou(node_id)["ou_label"]
        if domain and not base.startswith(domain):
            return f"{domain} // {base}"
        return base

    def dn(self, node_id: str) -> str:
        return self._store.get(node_id, {}).get("dn", "")

    def sam(self, node_id: str) -> str:
        return self._store.get(node_id, {}).get("sam", _sam_from_id(node_id))

    def node_type(self, node_id: str) -> str:
        return self._store.get(node_id, {}).get("node_type", _type_from_id(node_id))

    def privilege_proximity(self, node_id: str) -> Optional[int]:
        """
        Graph-derived distance to nearest Tier-0 group.
        Returns None if no path to Tier-0 exists in the graph.
        """
        return self._proximity.get(node_id, None)

    def node_context(self, node_id: str, domain: str = "") -> Dict:
        """
        Standard structural context block for any node_id.
        Shape is consistent across all refined output sections.
        """
        prox = self.privilege_proximity(node_id)
        return {
            "node_id":             node_id,
            "sam":                 self.sam(node_id),
            "node_type":           self.node_type(node_id),
            "dn":                  self.dn(node_id),
            "ou_path":             self.ou_path(node_id),
            "ou_path_label":       self.ou_label(node_id, domain),
            "privilege_proximity": prox,
            "is_tier0":            prox == 0,
        }

    def __len__(self) -> int:
        return len(self._store)


# ---------------------------------------------------------------------------
# Control-edge density tracker (feeds heatmap)
# ---------------------------------------------------------------------------

class OUControlDensity:
    """
    Tracks per OU path label:
        control_edges    — number of dangerous ACL edges originating from OU
        unique_targets   — set of distinct target SAMs influenced
        da_reachable     — any identity in OU has a Tier-0 path
        involved         — set of SAMs seen
    """

    def __init__(self) -> None:
        self._data: Dict[str, Dict] = defaultdict(lambda: {
            "control_edges":       0,
            "unique_targets":      set(),
            "da_reachable":        False,
            "involved_identities": set(),
        })

    def record(
        self,
        source_label: str,
        target_sam: str,
        source_sam: str,
        da_reachable: bool,
    ) -> None:
        entry = self._data[source_label]
        entry["control_edges"]        += 1
        entry["unique_targets"].add(target_sam)
        entry["involved_identities"].add(source_sam)
        if da_reachable:
            entry["da_reachable"] = True

    def serialise(self) -> Dict[str, Dict]:
        return {
            label: {
                "control_edges":       e["control_edges"],
                "unique_target_count": len(e["unique_targets"]),
                "da_reachable":        e["da_reachable"],
                "involved_identities": sorted(e["involved_identities"]),
            }
            for label, e in self._data.items()
        }


# ---------------------------------------------------------------------------
# Core Refiner
# ---------------------------------------------------------------------------

class AuthorizationRefiner:
    """
    Behaviour-aware prioritization engine.

    Load order (per review feedback):
        1. graph JSON  -> IdentityRegistry (primary, authoritative, full DN coverage)
        2. analysis JSON -> behavioral findings to enrich and rank
        3. Analysis overlay -> fills any node IDs absent from graph

    Output: all findings preserved, annotated with exploitability scores,
    privilege proximity, OU context, and priority flags for the visualizer.
    """

    def __init__(
        self,
        analysis_path: str,
        graph_json_path: Optional[str] = None,
    ) -> None:
        self.analysis_path   = Path(analysis_path)
        self.graph_json_path = graph_json_path

        # ── Load analysis ──────────────────────────────────────────────
        print(f"[*] Loading analysis: {self.analysis_path}")
        with open(self.analysis_path, "r", encoding="utf-8-sig") as f:
            self.analysis: Dict = json.load(f)

        self.metadata: Dict = self.analysis.get("metadata", {})
        self.domain: str    = self.metadata.get("domain", "")

        # ── Build IdentityRegistry ─────────────────────────────────────
        print("[*] Building IdentityRegistry …")
        self.reg = IdentityRegistry()

        # Step 1: graph JSON is the authoritative, primary source
        graph_loaded    = False
        graph_path      = self._resolve_graph_path(graph_json_path)
        if graph_path:
            try:
                with open(graph_path, "r", encoding="utf-8-sig") as f:
                    graph_data = json.load(f)
                self.reg.load_from_graph(graph_data)
                graph_loaded = True
            except Exception as exc:
                print(f"    [!] Graph JSON load failed ({exc}) — falling back to analysis overlay")

        # Step 2: overlay analysis references (gap-filler or sole source)
        self.reg.overlay_from_analysis(self.analysis)

        # Step 3: compute graph-derived privilege proximity (requires graph)
        if graph_loaded:
            self.reg.compute_privilege_proximity()
        else:
            print("    [!] Graph JSON unavailable — privilege_proximity will be None for all nodes")

        # ── Control-edge density (populated during ACL refinement pass) ─
        self._ctrl_density = OUControlDensity()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def refine(self) -> Dict:
        """Run all refinement passes and return the complete refined structure."""
        print("[*] Running refinement passes …")

        acl_findings     = self._refine_acl_abuse()
        da_entries       = self._refine_da_paths()
        kerb_entries     = self._refine_kerberoastable()
        delegation_entries = self._refine_delegation()

        # Heatmap must run AFTER all passes so ctrl_density is fully populated
        heatmap = self._build_ou_risk_heatmap(
            acl_findings, da_entries, kerb_entries, delegation_entries
        )

        return {
            "metadata": {
                **self.metadata,
                "refined_at":      datetime.utcnow().isoformat() + "Z",
                "refiner_version": "2.0.0",
            },
            "summary": self._build_summary(
                acl_findings, da_entries, kerb_entries, delegation_entries
            ),
            "high_risk_ou_acl_paths": acl_findings,
            "da_path_ou_map":         da_entries,
            "kerberoastable_ou_map":  kerb_entries,
            "delegation_ou_map":      delegation_entries,
            "ou_risk_heatmap":        heatmap,
        }

    # ------------------------------------------------------------------
    # Pass 1 — ACL abuse chains
    # ------------------------------------------------------------------

    def _refine_acl_abuse(self) -> List[Dict]:
        """
        Enrich every ACL abuse chain with:
            - OU path context for source and target
            - privilege_proximity for both endpoints
            - OU trajectory for the full abuse chain
            - priority_flag  (visualizer hint — NOT a filter)

        ALL findings are preserved. No silent dropping.
        """
        findings: List[Dict] = []

        for target_id, chains in self.analysis.get("acl_abuse_chains", {}).items():
            for chain in chains:
                source_id   = chain.get("source", "")
                permission  = chain.get("full_permission") or chain.get("permission", "")
                chain_nodes = chain.get("abuse_chain", [source_id, target_id])
                chain_len   = chain.get("chain_length", len(chain_nodes))
                
                # Feed control-edge density for heatmap
                src_label    = self.reg.ou_label(source_id, self.domain)
                src_sam      = self.reg.sam(source_id)
                tgt_sam      = self.reg.sam(target_id)
                da_reachable = self.reg.privilege_proximity(source_id) is not None
                self._ctrl_density.record(src_label, tgt_sam, src_sam, da_reachable)

                findings.append({
                    "finding_type":         "acl_abuse",
                    
                    "source": self.reg.node_context(source_id, self.domain),
                    "target": self.reg.node_context(target_id, self.domain),

                    "acl": {
                        "edge_type":         chain.get("permission", ""),
                        "full_permission":   permission,
                        "acl_path_direction": (
                            f"{self.reg.ou_label(source_id, self.domain)}"
                            f" -> "
                            f"{self.reg.ou_label(target_id, self.domain)}"
                        ),
                    },

                    "escalation_chain": {
                        "nodes":         chain_nodes,
                        "length":        chain_len,
                        "ou_trajectory": self._chain_trajectory(chain_nodes),
                        "explanation":   chain.get("explanation", ""),
                    },

                    "authorities_gained": chain.get("authorities_gained", []),
                })

        # Sort: closest to Tier-0 first, then shorter chains
        findings.sort(
            key=lambda f: (
                f["source"].get("privilege_proximity", 999),
                f["escalation_chain"]["length"]
            )
        )
        
        return findings

    # ------------------------------------------------------------------
    # Pass 2 — Domain Admin paths
    # ------------------------------------------------------------------

    def _refine_da_paths(self) -> List[Dict]:
        """
        Map each identity with a DA path to its OU context and the
        OU trajectory of its shortest escalation route.

        Also flags proximity_analysis_agreement: if the graph proximity
        BFS did NOT find a path but the analyzer did, that is a structural
        signal worth surfacing (e.g. edge coverage gap in graph build).
        """
        entries: List[Dict] = []

        for node_id, data in self.analysis.get("domain_admin_paths", {}).items():
            paths = data.get("paths", [])
            if not paths:
                continue

            shortest = min(paths, key=len)
            prox     = self.reg.privilege_proximity(node_id)

            entries.append({
                **self.reg.node_context(node_id, self.domain),
                "path_count":                    data.get("path_count", len(paths)),
                "shortest_path_length":          data.get("shortest_path_length", len(shortest)),
                "shortest_path":                 shortest,
                "shortest_path_ou_trajectory":   self._chain_trajectory(shortest),
                # Agreement check: graph BFS vs analyzer path-finding
                "proximity_analysis_agreement":  prox is not None,
            })

        # Sort: closest to Tier-0 first, then by path length
        entries.sort(key=lambda e: (
            e["privilege_proximity"] if e["privilege_proximity"] is not None else 9999,
            e["shortest_path_length"],
        ))
        print(f"    [+] DA path map: {len(entries)} identities mapped")
        return entries

    # ------------------------------------------------------------------
    # Pass 3 — Kerberoastable identities
    # ------------------------------------------------------------------

    def _refine_kerberoastable(self) -> List[Dict]:
        """
        Map Kerberoastable identities to their OU paths and privilege proximity.

        v1 risk elevation based on OU tier (OU name heuristic) is REMOVED.
        Privilege proximity replaces it entirely:
            proximity <= 2  -> graph says this account is structurally close to Tier-0
            paths_to_da > 0 -> analyzer found a concrete DA escalation path

        ALL findings are preserved. priority_flag is set but visualizer filters.
        """
        entries: List[Dict] = []

        for node_id, data in self.analysis.get("kerberoastable_analysis", {}).items():
            prox        = self.reg.privilege_proximity(node_id)
            paths_to_da = data.get("paths_to_da", 0)
           

            entries.append({
                **self.reg.node_context(node_id, self.domain),
                "spns":                 data.get("spns", []),
                "spn_count":            data.get("spn_count", 0),
                "paths_to_da":          paths_to_da,
                "shortest_path_length": data.get("shortest_path_length"),
                "enabled":              data.get("enabled", True),
                
            })

        entries.sort(key=lambda e: (
            e["privilege_proximity"] if e["privilege_proximity"] is not None else 9999,
            e["shortest_path_length"] or 9999,
        ))
        print(f"    [+] Kerberoastable OU map: {len(entries)} entries")
        return entries

    # ------------------------------------------------------------------
    # Pass 4 — Delegation risks
    # ------------------------------------------------------------------

    def _refine_delegation(self) -> List[Dict]:
        """
        Map delegation risks to OU ACL paths for source and target.
        Adds privilege proximity for both endpoints.
        """
        entries: List[Dict] = []

        for risk in self.analysis.get("delegation_risks", []):
            source_id  = risk.get("source", "")
            target_id  = risk.get("target", "")
            risk_level = risk.get("risk_level", "MEDIUM")

            entries.append({
                "source":            self.reg.node_context(source_id, self.domain),
                "target":            self.reg.node_context(target_id, self.domain),
                "delegation_type":   risk.get("delegation_type", ""),
                "edge_type":         risk.get("edge_type", ""),
                "conditional":       risk.get("conditional", False),
                "conditions":        risk.get("conditions", []),
                "has_high_privilege": risk.get("has_high_privilege", False),
                "acl_path_direction": (
                    f"{self.reg.ou_label(source_id, self.domain)}"
                    f" -> "
                    f"{self.reg.ou_label(target_id, self.domain)}"
                ),
                
            })

        entries.sort(key=lambda e: (
            e["source"]["privilege_proximity"] if e["source"]["privilege_proximity"] is not None else 9999
        ))
        print(f"    [+] Delegation OU map: {len(entries)} entries")
        return entries

    # ------------------------------------------------------------------
    # OU risk heatmap
    # ------------------------------------------------------------------

    def _build_ou_risk_heatmap(
        self,
        acl_findings:       List[Dict],
        da_entries:         List[Dict],
        kerb_entries:       List[Dict],
        delegation_entries: List[Dict],
    ) -> List[Dict]:
        """
        Aggregate findings per OU path label.

        Each OU entry tracks:
            control_edges                      -- ACL edges originating FROM this OU
            da_reachable                       -- any identity here has Tier-0 path
            min_privilege_proximity            -- closest any identity here is to Tier-0
            involved_identities                -- SAMs present in this OU across findings
        """
        # ou_label -> counters
        heatmap: Dict[str, Dict] = defaultdict(lambda: {
            "ou_path_label":           "",
            "ou_path":                 [],
            "total":                   0,
            "control_edges":           0,
            "da_reachable":            False,
            "min_privilege_proximity": None,
            "involved_identities":     set(),
        })

        def _update_proximity(label: str, prox: Optional[int]) -> None:
            entry = heatmap[label]
            if prox is not None:
                cur = entry["min_privilege_proximity"]
                entry["min_privilege_proximity"] = (
                    prox if cur is None else min(cur, prox)
                )

        def _record(node_id: str,) -> None:
            if not node_id:
                return
            ou_path = self.reg.ou_path(node_id)
            label   = self.reg.ou_label(node_id, self.domain)
            entry   = heatmap[label]

            if not entry["ou_path_label"]:
                entry["ou_path_label"] = label
                entry["ou_path"]       = ou_path
            
            entry["total"] += 1
            entry["involved_identities"].add(self.reg.sam(node_id))
            
            prox = self.reg.privilege_proximity(node_id)
            if prox is not None:
                entry["da_reachable"] = True
            
            _update_proximity(label, prox)

        # ACL abuse: source and target both contribute to their respective OUs
        for f in acl_findings:
            _record(f["source"]["node_id"])
            _record(f["target"]["node_id"])

        # DA paths
        for e in da_entries:
            _record(e["node_id"])

        # Kerberoastable
        for e in kerb_entries:
            _record(e["node_id"])

        # Delegation: source and target
        for e in delegation_entries:
            _record(e["source"]["node_id"])
            _record(e["target"]["node_id"])

        # Merge control-edge density (populated during ACL pass)
        ctrl = self._ctrl_density.serialise()
        for label, cdata in ctrl.items():
            entry = heatmap[label]
            entry["control_edges"] += cdata["control_edges"]
            # unique_targets in heatmap is a set; cdata has pre-counted int
            # so we track control-density as additive count here
            if not entry["ou_path_label"]:
                entry["ou_path_label"] = label

        # Serialise sets -> sorted lists
        result = []
        for entry in heatmap.values():
            if not entry["ou_path_label"]:
                continue
            # Pull unique_target count from ctrl_density for this label
            ctrl_entry   = ctrl.get(entry["ou_path_label"], {})
            unique_count = ctrl_entry.get("unique_target_count", 0)

            result.append({
                "ou_path_label":           entry["ou_path_label"],
                "ou_path":                 entry["ou_path"],
                "total":                   entry["total"],
                "control_edges":           entry["control_edges"],
                "unique_targets":          unique_count,
                "da_reachable":            entry["da_reachable"],
                "min_privilege_proximity": entry["min_privilege_proximity"],
                "involved_identities":     sorted(entry["involved_identities"]),
            })

        result.sort(key=lambda e: (
            0 if e["da_reachable"] else 1,
            e["min_privilege_proximity"] if e["min_privilege_proximity"] is not None else 9999,
            -e["control_edges"],
        ))

        print(f"    [+] OU risk heatmap: {len(result)} distinct OU paths")
        return result

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _build_summary(
        self,
        acl_findings:       List[Dict],
        da_entries:         List[Dict],
        kerb_entries:       List[Dict],
        delegation_entries: List[Dict],
    ) -> Dict:
        
        return {
            "domain": self.domain,
            "collection_date": self.metadata.get("collection_date", ""),
            "refined_at": datetime.utcnow().isoformat() + "Z",

            "total_identities_in_analysis": self.analysis.get("summary", {}).get(
                "total_identities", 0
            ),
            "registry_size": len(self.reg),

            "total_acl_findings": len(acl_findings),
            "identities_with_da_paths": len(da_entries),
            "kerberoastable_identities": len(kerb_entries),
            "delegation_risks": len(delegation_entries),
        }

        

    # ------------------------------------------------------------------
    # Chain OU trajectory  (uses cached registry lookups)
    # ------------------------------------------------------------------

    def _chain_trajectory(self, chain_nodes: List[str]) -> List[Dict]:
        """
        Return OU context for each node in a chain.
        Uses the registry's per-node cache — no repeated DN string ops.
        """
        return [self.reg.node_context(nid, self.domain) for nid in chain_nodes]

    # ------------------------------------------------------------------
    # Graph path resolution
    # ------------------------------------------------------------------

    def _resolve_graph_path(self, explicit: Optional[str]) -> Optional[str]:
        """
        Resolve the graph JSON path to use.

        Priority:
            1. Explicitly provided argument
            2. Auto-detect beside analysis file (_analysis.json -> _graph.json)
            3. None (graph unavailable; registry falls back to analysis overlay)
        """
        if explicit:
            p = Path(explicit)
            if p.exists():
                return str(p)
            print(f"    [!] Explicit graph path not found: {explicit}")
            return None

        candidate = str(self.analysis_path).replace("_analysis.json", "_graph.json")
        if Path(candidate).exists():
            print(f"    [*] Auto-detected graph JSON: {candidate}")
            return candidate

        print("    [!] No graph JSON found — proceeding without DN / proximity enrichment")
        return None


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

def save_refined(refined: Dict, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8-sig") as f:
        json.dump(refined, f, indent=2)
    print(f"[+] Refined output saved: {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 80)
    print("Authorization OU ACL Path Refiner  v2")
    print("=" * 80)
    print()

    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print("Usage:")
        print("  python refiner.py <analysis_json> [<graph_json>] [--output <path>]")
        print()
        print("  analysis_json   ad_authorization_state_analysis.json  (required)")
        print("  graph_json      ad_authorization_state_graph.json      (recommended)")
        print("                  Auto-detected beside analysis file if omitted.")
        print("  --output        Output path  (default: ad_authorization_state_refined.json)")
        print()
        print("Pipeline:")
        print("  graph_builder.py -> ad_authorization_state_graph.json")
        print("  analyzer.py      -> ad_authorization_state_analysis.json")
        print("  refiner.py       -> ad_authorization_state_refined.json")
        print("  visualizer_2.py  -> ad_authorization_state_report_refined.html")
        sys.exit(0)

    analysis_path               = args[0]
    graph_json_path: Optional[str] = None
    output_path                 = "ad_authorization_state_refined.json"

    i = 1
    while i < len(args):
        if args[i] == "--output" and i + 1 < len(args):
            output_path = args[i + 1]
            i += 2
        elif not args[i].startswith("--") and graph_json_path is None:
            graph_json_path = args[i]
            i += 1
        else:
            i += 1

    if not Path(analysis_path).exists():
        print(f"[-] Analysis file not found: {analysis_path}")
        sys.exit(1)

    try:
        refiner = AuthorizationRefiner(
            analysis_path=analysis_path,
            graph_json_path=graph_json_path,
        )
        refined = refiner.refine()
        save_refined(refined, output_path)
    except Exception as exc:
        print(f"[-] Refiner error: {exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    summary = refined.get("summary", {})
    print()
    print("=== Refinement Summary ===")
    print(f"  Domain                        : {summary.get('domain', 'Unknown')}")
    print(f"  Registry size                 : {summary.get('registry_size', 0)} nodes")
    print(f"  Total ACL findings            : {summary.get('total_acl_findings', 0)}")
    print(f"  High-priority ACL findings    : {summary.get('high_priority_acl_findings', 0)}")
    print(f"  Avg exploitability score      : {summary.get('avg_exploitability_score', 0.0)}")
    print(f"  Identities with DA paths      : {summary.get('identities_with_da_paths', 0)}")
    print(f"  Kerberoastable identities     : {summary.get('kerberoastable_identities', 0)}")
    print(f"  Delegation risks              : {summary.get('delegation_risks', 0)}")
    print()
    print("[+] Refiner complete!")
    print(f"    Next step: python visualizer_2.py {output_path}")


if __name__ == "__main__":
    main()