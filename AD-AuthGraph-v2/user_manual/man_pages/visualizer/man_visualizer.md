# VISUALIZER.PY(1)

## NAME

**visualizer.py** (module: `visualizer_refined.py`) — render a refiner.py output file as a static HTML authorization intelligence report

## SYNOPSIS

```
python visualizer.py <refined_json> [--output <path>]
python visualizer.py -h | --help
```

## DESCRIPTION

**visualizer.py** is the final, report-rendering stage of the AD-AuthGraph-v2 pipeline. It consumes the refined findings JSON produced by `refiner.py` and renders a single, self-contained, static HTML report — no server, no build step, no JavaScript framework. The internal module name embedded in the source (`visualizer_refined.py`) and the CLI usage text reflect that this is specifically the *refined*-pipeline visualizer, as distinct from any earlier/simpler visualizer this project may have had.

**Design intent** (per the module docstring): a "classified security briefing" aesthetic — a stark, monochrome, typography-first instrument with a single accent color (surgical red) reserved for CRITICAL findings. No glow effects, no gradients. Fonts are DM Mono (body/data) and Cormorant (headings), loaded from Google Fonts via `@import` in the generated HTML's `<style>` block.

## REQUIREMENTS

* Python 3.x (standard library only: `json`, `sys`, `html`, `pathlib`, `datetime`, `typing`).
* No packages to install for *generating* the report.
* **Viewing** the generated HTML in a browser requires internet access to fetch the Google Fonts stylesheet (`fonts.googleapis.com`) referenced in the embedded CSS; without it the report still renders correctly, just with fallback fonts (the CSS specifies `Georgia, serif` and generic `monospace` fallbacks).

## USAGE

```
python visualizer.py <refined_json> [--output <path>]
```

`<refined_json>` (required)
: Path to the refiner's output JSON (e.g. `ad_authorization_state_refined.json`).

`--output <path>`
: Output HTML file path. Default: derived from the input filename by stripping a trailing `_refined` from the stem and appending `_report_refined.html` (e.g. `ad_authorization_state_refined.json` → `ad_authorization_state_report_refined.html`).

`-h`, `--help`
: Print usage and pipeline position, exit 0.

## PIPELINE POSITION

```
refiner.py       -> ad_authorization_state_refined.json
visualizer.py     -> ad_authorization_state_report_refined.html
```

## REPORT SECTIONS

The module docstring lists seven intended sections; the sections actually assembled by `build_report()` are, in order:

1. **Header** — domain, collection date, refinement timestamp, report generation timestamp.
2. **Executive Summary** — KPI tiles (ACL Abuse Chains, DA Path Holders, Kerberoastable count, Delegation Risks, Registry Size), each with alert/warn styling when non-zero, plus an optional "Top Exploitable Chains" mini-table if `summary.top_exploitable_chains` is present in the input.
3. **High-Risk ACL Abuse Chains** — one card per finding: the full node chain as chips, an exploitability score bar, risk badge, OU direction, permission, chain length, source/target privilege proximity, and up to 6 "authorities gained" chips.
4. **OU Risk Heatmap** — *listed in the docstring but currently a no-op*: `render_ou_heatmap()` unconditionally returns an empty string regardless of the heatmap data passed in, so **no heatmap content is rendered in the current source**, even though the refiner's `ou_risk_heatmap` array is still read from the input JSON.
5. **Domain Admin Privilege Paths** — one table row per identity: shortest path (as chips), path count, hop count, privilege proximity, OU label, and a graph/analyzer agreement marker (✓ / △, from `proximity_analysis_agreement`).
6. **Kerberoastable Identities** — one card per identity: node chip, risk badge, DA-path badge, enabled/disabled state, SPN chips, OU, SPN count, DA path count.
7. **Delegation Risks** — one card per risk: source → target chips, risk badge, delegation type, conditions, OU direction, source proximity.

**Graph Explorer** (listed as item 7 in the module docstring, "force-directed, ACL-aware") is **not implemented** in this source — there is no corresponding render function, no `<script>` block, and no charting/force-layout library reference (e.g. D3) anywhere in the file, and `build_report()` never calls anything of that name. This was a deliberate cut, not an oversight: at enterprise scale (the scale this pipeline is explicitly designed for — see the top-level README), a full force-directed rendering of the authorization graph becomes an unreadable, unnavigable hairball rather than a useful visual, so the feature was dropped in favor of the structured table/card sections above.

## DATA DEPENDENCIES ON UPSTREAM FIELDS

This visualizer reads several fields defensively via `dict.get(key, default)`, meaning **it will not error if these are absent** — it just renders defaults. As of the current `refiner.py` (which no longer computes exploitability/priority scoring), the following fields are always absent from its input and will always render at their default:

| Field read by visualizer | Default used | Effect |
|---|---|---|
| `finding.priority_flag` (ACL / Kerberoastable / Delegation) | `False` | No priority left-border highlight is ever shown; "N high-priority" counts always render as 0. |
| `finding.exploitability_score` (ACL chains) | `0.0` | Exploitability score bar always renders at 0. |
| `summary.top_exploitable_chains` | `[]` | The "Top Exploitable Chains" mini-table under Executive Summary never renders. |
| `summary.avg_exploitability_score`, `summary.high_priority_acl_findings`, `summary.high_priority_kerberoastable` | `0` / `0.0` | Read but not currently surfaced as their own KPI tile in this version's `render_summary()`; effectively unused. |

None of this causes an error — the report renders cleanly either way — but be aware that scoring/priority-dependent visual emphasis (colored left borders, the top-chains table, score bars) will be visually inert until/unless `refiner.py` is extended to populate these fields again.

## OUTPUT

A single static HTML file, UTF-8 encoded, with all CSS inlined in a `<style>` block (one external `@import` for Google Fonts) and no external JS dependencies. Printed to stdout after generation: output path, file size in KB, and a `file:///` URL for opening it directly in a browser.

## EXIT STATUS

`0`
: Successful report generation, or `--help`.

`1`
: `<refined_json>` does not exist. (Other errors — e.g. malformed JSON — are not caught explicitly by `main()` and will propagate as an uncaught Python exception/traceback.)

## EXAMPLES

Default output path:
```
python visualizer.py ad_authorization_state_refined.json
```
produces `ad_authorization_state_report_refined.html`.

Explicit output path:
```
python visualizer.py state_5_refined.json --output state_5_report.html
```

## NOTES / LIMITATIONS

* **OU Risk Heatmap is currently disabled.** `render_ou_heatmap()` returns `""` unconditionally; the section is a documented-but-dark feature. If heatmap visualization is wanted again, this function needs to be restored to actually render the `heatmap` list it's given (mirroring the pattern used by the other `render_*` functions).
* **Graph Explorer is unimplemented by design, not merely disabled.** It was cut rather than built out: at the enterprise scale this pipeline targets, a force-directed rendering of the full authorization graph becomes visually convoluted and unnavigable well before it's large enough to be interesting, so the structured table/card sections carry that job instead. There is no partial implementation to re-enable — building it would mean starting from scratch, and would likely need graph sampling/filtering (e.g. scoping to a single OU, identity, or finding) to stay usable at scale rather than rendering the whole domain at once.
* Exploitability/priority-scoring visual elements (score bars, priority borders, top-chains table) are present in the template but will stay at their zero/empty defaults unless `refiner.py` is extended to emit `exploitability_score`, `priority_flag`, and `top_exploitable_chains` again — this is a direct consequence of the risk-scoring removal from the refiner, not a bug in this file.
* The generated report embeds a live `@import` of Google Fonts; for air-gapped or offline review environments, the report will still render (using fallback fonts) but will attempt an external network request each time it's opened in a browser with dev tools/network monitoring active. There is no offline-fonts/self-hosted-fonts option in this source.
* `main()` does not wrap `build_report()` in a try/except, so a malformed or unexpectedly-shaped `refined_json` (e.g. missing top-level keys entirely) will surface as a raw Python traceback rather than a clean `[-] Error: ...` message, unlike the file-not-found case which is checked explicitly beforehand.

## SEE ALSO

`refiner.py`(1), `graph_builder.py`(1), `analyzer`(1), AD-AuthGraph-v2 USER_MANUAL.md
