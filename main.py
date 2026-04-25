"""
main.py  —  AD Authorization Graph Analysis Pipeline

Orchestrates the complete four-step workflow:

    Step 1  graph_builder.py   AD state JSON  →  *_graph.json
    Step 2  analyzer.py        *_graph.json   →  *_analysis.json
    Step 3  refiner.py         *_analysis.json →  *_refined.json
    Step 4  visualizer.py      *_refined.json  →  *_report_refined.html

Additionally supports:
    --compare   Side-by-side analysis of two AD state snapshots

Author: Siddharth Ray Chaudhuri
Date: 2026
Purpose: Authorization Graph Modeling Project
"""

import sys
import argparse
import json
import traceback
from pathlib import Path
from datetime import datetime

# ── Pipeline modules ──────────────────────────────────────────────────────────
from graph_builder import AuthorizationGraph
from analyzer      import AuthorizationAnalyzer
from refiner       import AuthorizationRefiner, save_refined
from visualizer    import build_report as build_html_report


# ── Optional matplotlib visualizer (PNG output) ───────────────────────────────
try:
    import matplotlib
    matplotlib.use("Agg")
    from visualizer_matplotlib import GraphVisualizer
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


# =============================================================================
# Pipeline class
# =============================================================================

class Pipeline:
    """
    Orchestrates graph_builder → analyzer → refiner → visualizer in sequence.

    File naming convention (all derived from the input file stem):
        <stem>_graph.json           — graph_builder output
        <stem>_analysis.json        — analyzer output
        <stem>_refined.json         — refiner output
        <stem>_report_refined.html  — visualizer output (refined)
        <stem>_graph.png            — optional matplotlib PNG
    """

    def __init__(
        self,
        input_file: str,
        output_dir: str = None,
        verbose:    bool = True,
    ) -> None:
        self.input_file = Path(input_file)
        self.verbose    = verbose

        if not self.input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        # Output directory
        if output_dir:
            self.output_dir = Path(output_dir)
            self.output_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.output_dir = self.input_file.parent

        # Derive consistent base name from input file stem
        self.base_name = self.input_file.stem

        # ── File paths for every stage output ─────────────────────────────
        self.graph_json    = self.output_dir / f"{self.base_name}_graph.json"
        self.analysis_json = self.output_dir / f"{self.base_name}_analysis.json"
        self.refined_json  = self.output_dir / f"{self.base_name}_refined.json"
        self.report_html   = self.output_dir / f"{self.base_name}_report_refined.html"
        self.graph_png     = self.output_dir / f"{self.base_name}_graph.png"

        self._banner("AD AUTHORIZATION GRAPH ANALYSIS PIPELINE")
        self.log(f"Input:  {self.input_file}")
        self.log(f"Output: {self.output_dir}")
        self.log("")

    # ── Logging ───────────────────────────────────────────────────────────────

    def log(self, message: str = "") -> None:
        if self.verbose:
            print(message)

    def _banner(self, title: str) -> None:
        if self.verbose:
            print("=" * 80)
            print(title)
            print("=" * 80)

    def _divider(self) -> None:
        if self.verbose:
            print("-" * 80)

    # =========================================================================
    # Step 1 — graph_builder.py
    # =========================================================================

    def step_1_build_graph(self) -> AuthorizationGraph:
        """
        Build the authorization graph from the raw AD state JSON.

        Produces:  <base>_graph.json
        Returns:   AuthorizationGraph instance (graph object kept in memory
                   so the optional PNG step can reuse it without re-loading).
        """
        self.log("[STEP 1/4] Building Authorization Graph")
        self._divider()

        graph = AuthorizationGraph()

        if not graph.load_from_json(str(self.input_file)):
            raise RuntimeError(
                "graph_builder failed to load the input file. "
                "Check that it is a valid AD authorization state JSON."
            )

        if not graph.export_graph_data(str(self.graph_json)):
            raise RuntimeError(
                f"graph_builder failed to export graph to: {self.graph_json}"
            )
        self.log(f"[+] Graph exported:  {self.graph_json}")

        stats = graph.get_statistics()
        self.log("[+] Graph Statistics:")
        self.log(f"    Nodes:     {stats['nodes']}")
        self.log(f"    Edges:     {stats['edges']}")
        self.log(f"    Users:     {stats['users']}")
        self.log(f"    Groups:    {stats['groups']}")
        self.log(f"    Computers: {stats['computers']}")
        self.log("")

        return graph

    # =========================================================================
    # Step 2 — analyzer.py
    # =========================================================================

    def step_2_analyze(self) -> AuthorizationAnalyzer:
        """
        Analyze the authorization graph for privilege escalation paths,
        Kerberoastable identities, ACL abuse chains, and delegation risks.

        Consumes: <base>_graph.json
        Produces: <base>_analysis.json
        Returns:  AuthorizationAnalyzer instance (kept for compare mode).
        """
        self.log("[STEP 2/4] Analyzing Authorization Graph")
        self._divider()

        # Analyzer accepts the graph JSON path directly — no redundant rebuild
        analyzer = AuthorizationAnalyzer(str(self.graph_json))

        # generate_report() writes the analysis JSON and returns a text summary
        analyzer.generate_report(output_file=str(self.analysis_json))

        # Pull counts from the cached analysis for the console summary
        da_paths = analyzer.find_domain_admin_paths()
        kerb     = analyzer.identify_kerberoastable_paths()
        acl      = analyzer.identify_acl_abuse_paths()
        deleg    = analyzer.identify_delegation_risks()

        self.log("")
        self.log("[+] Analysis Summary:")
        self.log(f"    Domain Admin Paths:       {len(da_paths)}")
        self.log(f"    Kerberoastable Identities:{len(kerb)}")
        self.log(f"    ACL Abuse Chains:         {len(acl)}")
        self.log(f"    Delegation Risks:         {len(deleg)}")
        self.log(f"[+] Analysis saved:  {self.analysis_json}")
        self.log("")

        return analyzer

    # =========================================================================
    # Step 3 — refiner.py
    # =========================================================================

    def step_3_refine(self) -> None:
        """
        Enrich the analysis findings with OU ACL path context, privilege
        proximity scores, exploitability weights, and a control-edge heatmap.

        Consumes: <base>_analysis.json  +  <base>_graph.json
        Produces: <base>_refined.json
        """
        self.log("[STEP 3/4] Refining Analysis (OU ACL Path Context)")
        self._divider()

        refiner = AuthorizationRefiner(
            analysis_path   = str(self.analysis_json),
            graph_json_path = str(self.graph_json),
        )

        refined = refiner.refine()
        save_refined(refined, str(self.refined_json))

        summary = refined.get("summary", {})
        self.log("")
        self.log("[+] Refinement Summary:")
        self.log(f"    Registry size:            {summary.get('registry_size', 0)} nodes")
        self.log(f"    ACL findings (total):     {summary.get('total_acl_findings', 0)}")
        self.log(f"    High-priority ACL:        {summary.get('high_priority_acl_findings', 0)}")
        self.log(f"    Identities with DA paths: {summary.get('identities_with_da_paths', 0)}")
        self.log(f"    Kerberoastable:           {summary.get('kerberoastable_identities', 0)}")
        self.log(f"    Delegation risks:         {summary.get('delegation_risks', 0)}")
        self.log(f"[+] Refined JSON saved: {self.refined_json}")
        self.log("")

    # =========================================================================
    # Step 4 — visualizer.py
    # =========================================================================

    def step_4_visualize(self) -> None:
        """
        Generate the interactive HTML report from the refined JSON.

        Consumes: <base>_refined.json
        Produces: <base>_report_refined.html
        """
        self.log("[STEP 4/4] Generating Interactive HTML Report")
        self._divider()

        # build_report() takes the refined JSON path and returns the full HTML
        html_content = build_html_report(str(self.refined_json))

        self.report_html.write_text(html_content, encoding="utf-8")

        size_kb = self.report_html.stat().st_size / 1024
        self.log(f"[+] HTML report saved: {self.report_html}")
        self.log(f"    Size: {size_kb:.1f} KB")
        self.log("")

    # =========================================================================
    # Optional Step — matplotlib PNG (unchanged from original main.py)
    # =========================================================================

    def step_optional_graph_png(self, graph: AuthorizationGraph) -> bool:
        """
        Generate a static graph PNG via matplotlib (optional, skipped gracefully
        when matplotlib / visualizer_matplotlib is not installed).
        """
        if not MATPLOTLIB_AVAILABLE:
            self.log("[OPTIONAL] Graph PNG (SKIPPED — matplotlib not available)")
            self.log("           pip install matplotlib  to enable")
            self.log("")
            return False

        self.log("[OPTIONAL] Generating Graph PNG")
        self._divider()

        try:
            visualizer = GraphVisualizer(graph)
            success = visualizer.visualize(
                output_file            = str(self.graph_png),
                layout                 = "spring",
                show_labels            = True,
                highlight_domain_admins= True,
            )
            if success:
                self.log(f"[+] Graph PNG saved: {self.graph_png}")
            else:
                self.log("[!] Graph PNG generation returned False")
            self.log("")
            return success

        except Exception as exc:
            self.log(f"[!] Graph PNG error: {exc}")
            self.log("")
            return False

    # =========================================================================
    # Main run method
    # =========================================================================

    def run(self, skip_graph_png: bool = False) -> bool:
        """
        Execute the full pipeline in order:
            Step 1  graph_builder
            Step 2  analyzer
            Step 3  refiner
            Step 4  visualizer (refined HTML report)
            +opt    matplotlib PNG

        Returns True on success, False on any step failure.
        """
        start_time = datetime.now()

        try:
            # ── Step 1 ────────────────────────────────────────────────────
            graph = self.step_1_build_graph()

            # ── Step 2 ────────────────────────────────────────────────────
            self.step_2_analyze()

            # ── Step 3 ────────────────────────────────────────────────────
            self.step_3_refine()

            # ── Step 4 ────────────────────────────────────────────────────
            self.step_4_visualize()

            # ── Optional PNG ──────────────────────────────────────────────
            if not skip_graph_png:
                self.step_optional_graph_png(graph)

            # ── Completion summary ─────────────────────────────────────────
            elapsed = (datetime.now() - start_time).total_seconds()
            self._banner("PIPELINE COMPLETE")
            self.log(f"Time Elapsed: {elapsed:.2f} seconds")
            self.log("")
            self.log("Generated Files:")
            self.log(f"  1. Graph JSON:    {self.graph_json}")
            self.log(f"  2. Analysis JSON: {self.analysis_json}")
            self.log(f"  3. Refined JSON:  {self.refined_json}")
            self.log(f"  4. HTML Report:   {self.report_html}")
            if not skip_graph_png and self.graph_png.exists():
                self.log(f"  5. Graph PNG:     {self.graph_png}")
            self.log("")
            self.log(f"Open report: file:///{self.report_html.resolve()}")
            self.log("")
            return True

        except Exception as exc:
            self.log("")
            self._banner("PIPELINE FAILED")
            self.log(f"Error: {exc}")
            traceback.print_exc()
            return False


# =============================================================================
# State comparison helper  (unchanged semantics, updated for new pipeline)
# =============================================================================

def compare_states(
    state1_file: str,
    state2_file: str,
    output_dir:  str = None,
) -> bool:
    """
    Compare two AD authorization state snapshots.

    For each state:
        graph_builder  →  analyzer  →  compare_states()
    The comparison result is printed to the console and saved as JSON.
    """
    print("=" * 80)
    print("AUTHORIZATION STATE COMPARISON")
    print("=" * 80)
    print(f"Current State:  {state1_file}")
    print(f"Previous State: {state2_file}")
    print("")

    out_dir = Path(output_dir) if output_dir else Path(state1_file).parent

    # ── Build + export both graphs ────────────────────────────────────────────
    print("[*] Building graphs …")

    graph1 = AuthorizationGraph()
    if not graph1.load_from_json(state1_file):
        print(f"[-] Failed to load current state: {state1_file}")
        return False
    graph1_json = out_dir / f"{Path(state1_file).stem}_graph.json"
    graph1.export_graph_data(str(graph1_json))

    graph2 = AuthorizationGraph()
    if not graph2.load_from_json(state2_file):
        print(f"[-] Failed to load previous state: {state2_file}")
        return False
    graph2_json = out_dir / f"{Path(state2_file).stem}_graph.json"
    graph2.export_graph_data(str(graph2_json))

    # ── Analyze both ──────────────────────────────────────────────────────────
    print("[*] Analyzing states …")
    analyzer1 = AuthorizationAnalyzer(str(graph1_json))
    analyzer2 = AuthorizationAnalyzer(str(graph2_json))

    # ── Compare ───────────────────────────────────────────────────────────────
    print("[*] Comparing states …")
    comparison = analyzer1.compare_states(analyzer2)

    # ── Print results ─────────────────────────────────────────────────────────
    print("")
    print("=" * 80)
    print("COMPARISON RESULTS")
    print("=" * 80)

    cs = comparison["current_state"]
    ps = comparison["previous_state"]
    dl = comparison["delta"]
    ch = comparison["changes"]

    print(f"\nCurrent State  ({state1_file}):")
    print(f"  Domain Admin Paths:   {cs['da_paths']}")
    print(f"  Total Edges:          {cs['total_edges']}")
    print(f"  Kerberoastable:       {cs['kerberoastable']}")

    print(f"\nPrevious State ({state2_file}):")
    print(f"  Domain Admin Paths:   {ps['da_paths']}")
    print(f"  Total Edges:          {ps['total_edges']}")
    print(f"  Kerberoastable:       {ps['kerberoastable']}")

    print(f"\nDeltas:")
    print(f"  DA Paths:             {dl['da_paths']:+d}")
    print(f"  Edges:                {dl['edges']:+d}")
    print(f"  Kerberoastable:       {dl['kerberoastable']:+d}")

    if ch.get("new_da_paths"):
        print(f"\n  New DA Paths ({len(ch['new_da_paths'])}):")
        for identity in ch["new_da_paths"]:
            print(f"    + {identity}")

    if ch.get("removed_da_paths"):
        print(f"\n  Removed DA Paths ({len(ch['removed_da_paths'])}):")
        for identity in ch["removed_da_paths"]:
            print(f"    - {identity}")

    if ch.get("new_kerberoastable"):
        print(f"\n  New Kerberoastable ({len(ch['new_kerberoastable'])}):")
        for identity in ch["new_kerberoastable"]:
            print(f"    + {identity}")

    # ── Save comparison JSON ──────────────────────────────────────────────────
    comparison_file = out_dir / "state_comparison.json"
    with open(comparison_file, "w", encoding="utf-8-sig") as f:
        json.dump(comparison, f, indent=2)
    print(f"\n[+] Comparison saved: {comparison_file}")
    print("")

    return True


# =============================================================================
# CLI entry point
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AD Authorization Graph Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Pipeline (default mode):
  graph_builder.py → analyzer.py → refiner.py → visualizer.py

Examples:
  # Full pipeline
  python main.py ad_authorization_state.json

  # Custom output directory
  python main.py ad_authorization_state.json --output ./reports

  # Skip optional matplotlib PNG (faster)
  python main.py ad_authorization_state.json --no-graph-png

  # Compare two AD state snapshots
  python main.py --compare blues_state1.json blues_state0.json

  # Quiet mode (suppress progress output)
  python main.py ad_authorization_state.json --quiet
        """,
    )

    parser.add_argument(
        "input_file",
        nargs="?",
        help="Path to AD authorization state JSON (from PowerShell collector)",
    )
    parser.add_argument(
        "--output", "-o",
        dest="output_dir",
        metavar="DIR",
        help="Output directory for all generated files (default: same as input)",
    )
    parser.add_argument(
        "--no-graph-png",
        action="store_true",
        help="Skip optional matplotlib graph PNG (faster, no extra dependency)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("CURRENT", "PREVIOUS"),
        help="Compare two AD state snapshots instead of running the full pipeline",
    )

    args = parser.parse_args()

    # ── Comparison mode ───────────────────────────────────────────────────────
    if args.compare:
        current, previous = args.compare
        success = compare_states(current, previous, args.output_dir)
        sys.exit(0 if success else 1)

    # ── Pipeline mode ─────────────────────────────────────────────────────────
    if not args.input_file:
        parser.print_help()
        sys.exit(1)

    try:
        pipeline = Pipeline(
            input_file = args.input_file,
            output_dir = args.output_dir,
            verbose    = not args.quiet,
        )
        success = pipeline.run(skip_graph_png=args.no_graph_png)
        sys.exit(0 if success else 1)

    except FileNotFoundError as exc:
        print(f"[-] Error: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"[-] Unexpected error: {exc}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
