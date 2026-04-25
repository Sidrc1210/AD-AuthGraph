"""
visualizer_refined.py  —  AD Authorization Refined Report Visualizer

Consumes:  ad_authorization_state_refined.json  (refiner.py output)
Produces:  ad_authorization_state_report_refined.html

Design intent:
    "Classified security briefing" aesthetic — stark precision instrument.
    Monochrome base with a single surgical red for CRITICAL findings.
    No glow, no gradients. Typography-first. Every pixel earns its place.

Sections rendered:
    1. Executive Summary (KPI tiles)
    2. High-Risk ACL Abuse Chains  (exploitability-ranked)
    3. OU Risk Heatmap              (control-edge density table)
    4. Domain Admin Privilege Paths
    5. Kerberoastable Identities
    6. Delegation Risks
    7. Graph Explorer               (force-directed, ACL-aware)

Author: Siddharth Ray Chaudhuri
Date: 2026
Purpose: Authorization Graph Modeling Project — Refined Pipeline Visualizer
"""

import json
import sys
import html as html_mod
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def esc(value: Any) -> str:
    """HTML-escape any value safely."""
    return html_mod.escape(str(value) if value is not None else "")


def risk_cls(level: str) -> str:
    level = (level or "").upper()
    return {
        "CRITICAL": "risk-critical",
        "HIGH":     "risk-high",
        "MEDIUM":   "risk-medium",
        "LOW":      "risk-low",
    }.get(level, "risk-low")


def node_cls(node_id: str) -> str:
    prefix = node_id.split(":")[0].lower() if ":" in node_id else "other"
    return prefix if prefix in {"user", "group", "computer", "spn"} else "other"


def sam(node_id: str) -> str:
    return node_id.split(":", 1)[1] if ":" in node_id else node_id


def render_chip(node_id: str, label: Optional[str] = None) -> str:
    cls = node_cls(node_id)
    text = esc(label or sam(node_id))
    return f'<span class="chip chip-{cls}">{text}</span>'


def render_path_chips(nodes: List[str]) -> str:
    parts = []
    for i, n in enumerate(nodes):
        parts.append(render_chip(n))
        if i < len(nodes) - 1:
            parts.append('<span class="arr">→</span>')
    return " ".join(parts)


def score_bar(score: float, max_score: float = 10.0) -> str:
    pct = min(100, int(score / max_score * 100))
    cls = "bar-critical" if score >= 8 else "bar-high" if score >= 6 else "bar-med"
    return (
        f'<div class="score-wrap">'
        f'<div class="score-bar {cls}" style="width:{pct}%"></div>'
        f'<span class="score-num">{score:.1f}</span>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

CSS = """
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:ital,wght@0,300;0,400;0,500;1,300&family=Cormorant:ital,wght@0,400;0,600;0,700;1,400&display=swap');

:root {
  --ink:        #0e0e0e;
  --ink2:       #2a2a2a;
  --ink3:       #5a5a5a;
  --ink4:       #909090;
  --rule:       #d8d8d8;
  --rule2:      #efefef;
  --paper:      #f7f6f3;
  --paper2:     #ffffff;
  --red:        #c0392b;
  --red2:       #e74c3c;
  --red-bg:     rgba(192,57,43,.06);
  --amber:      #b45309;
  --amber-bg:   rgba(180,83,9,.06);
  --slate:      #334155;
  --slate-bg:   rgba(51,65,85,.05);
  --mono:       'DM Mono', monospace;
  --serif:      'Cormorant', Georgia, serif;
  --r:          3px;
  --page:       1320px;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }

body {
  background: var(--paper);
  color: var(--ink);
  font-family: var(--mono);
  font-size: 13px;
  line-height: 1.65;
  min-height: 100vh;
}

/* ── Page wrapper ────────────────────────────────────── */
.page { max-width: var(--page); margin: 0 auto; padding: 0 32px 80px; }

/* ── Header ──────────────────────────────────────────── */
header {
  border-bottom: 2px solid var(--ink);
  padding: 36px 0 28px;
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
  flex-wrap: wrap;
}
.hdr-left { display: flex; flex-direction: column; gap: 6px; }
.hdr-eyebrow {
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: 4px;
  text-transform: uppercase;
  color: var(--ink3);
}
h1 {
  font-family: var(--serif);
  font-size: 42px;
  font-weight: 700;
  color: var(--ink);
  line-height: 1;
  letter-spacing: -.5px;
}
h1 em { font-style: italic; color: var(--red); font-weight: 400; }
.hdr-right {
  text-align: right;
  font-family: var(--mono);
  font-size: 10px;
  color: var(--ink3);
  line-height: 2;
}
.hdr-domain {
  font-size: 14px;
  font-weight: 500;
  color: var(--ink);
  font-family: var(--mono);
  letter-spacing: 1px;
}

/* ── Section ─────────────────────────────────────────── */
.section { margin-top: 48px; }
.section-hdr {
  display: flex;
  align-items: baseline;
  gap: 14px;
  border-bottom: 1px solid var(--ink);
  padding-bottom: 8px;
  margin-bottom: 22px;
}
.section-title {
  font-family: var(--serif);
  font-size: 22px;
  font-weight: 600;
  color: var(--ink);
  letter-spacing: -.2px;
}
.section-count {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--ink3);
  letter-spacing: 1px;
  text-transform: uppercase;
}

/* ── KPI tiles ───────────────────────────────────────── */
.kpi-row {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
  gap: 1px;
  border: 1px solid var(--rule);
  background: var(--rule);
}
.kpi {
  background: var(--paper2);
  padding: 20px 22px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.kpi-label {
  font-size: 9px;
  letter-spacing: 2.5px;
  text-transform: uppercase;
  color: var(--ink4);
}
.kpi-value {
  font-family: var(--serif);
  font-size: 44px;
  font-weight: 700;
  line-height: 1;
  color: var(--ink);
}
.kpi.kpi-alert  .kpi-value { color: var(--red); }
.kpi.kpi-warn   .kpi-value { color: var(--amber); }
.kpi-sub { font-size: 10px; color: var(--ink4); }

/* ── Risk badges ─────────────────────────────────────── */
.risk-critical { color: var(--red);   font-weight: 500; }
.risk-high     { color: var(--amber); font-weight: 500; }
.risk-medium   { color: var(--slate); }
.risk-low      { color: var(--ink4);  }

.badge {
  display: inline-block;
  font-family: var(--mono);
  font-size: 9px;
  font-weight: 500;
  letter-spacing: 1.2px;
  text-transform: uppercase;
  padding: 2px 7px;
  border-radius: var(--r);
}
.badge-critical { background: var(--red-bg);   color: var(--red);   border: 1px solid rgba(192,57,43,.25); }
.badge-high     { background: var(--amber-bg); color: var(--amber); border: 1px solid rgba(180,83,9,.25);  }
.badge-medium   { background: var(--slate-bg); color: var(--slate); border: 1px solid rgba(51,65,85,.2);   }
.badge-low      { background: var(--rule2);    color: var(--ink3);  border: 1px solid var(--rule);         }

/* ── Node chips ──────────────────────────────────────── */
.chip {
  display: inline-block;
  font-family: var(--mono);
  font-size: 11px;
  padding: 2px 8px;
  border-radius: var(--r);
  white-space: nowrap;
}
.chip-user     { background: rgba(14,14,14,.05);  border: 1px solid rgba(14,14,14,.15); }
.chip-group    { background: rgba(192,57,43,.07); border: 1px solid rgba(192,57,43,.2); color: var(--red); }
.chip-computer { background: rgba(180,83,9,.07);  border: 1px solid rgba(180,83,9,.2);  color: var(--amber); }
.chip-spn      { background: rgba(51,65,85,.07);  border: 1px solid rgba(51,65,85,.2);  color: var(--slate); }
.chip-other    { background: var(--rule2); border: 1px solid var(--rule); color: var(--ink3); }
.arr { color: var(--ink4); font-size: 12px; margin: 0 2px; }

/* ── Tables ──────────────────────────────────────────── */
.tbl-wrap { overflow-x: auto; }
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
thead th {
  font-family: var(--mono);
  font-size: 9px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--ink3);
  padding: 9px 14px;
  border-bottom: 1px solid var(--rule);
  text-align: left;
  white-space: nowrap;
  background: var(--paper2);
}
tbody tr { border-bottom: 1px solid var(--rule2); }
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: rgba(0,0,0,.018); }
tbody td {
  padding: 10px 14px;
  vertical-align: top;
  color: var(--ink2);
}

/* ── ACL finding cards ───────────────────────────────── */
.acl-cards { display: flex; flex-direction: column; gap: 1px; }
.acl-card {
  background: var(--paper2);
  border: 1px solid var(--rule);
  border-left: 3px solid var(--rule);
  padding: 16px 20px;
}
.acl-card.priority-critical { border-left-color: var(--red); background: var(--red-bg); }
.acl-card.priority-high     { border-left-color: var(--amber); }
.acl-card.priority-medium   { border-left-color: var(--slate); }

.acl-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 10px;
  flex-wrap: wrap;
}
.acl-chain-row {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  flex: 1;
}
.acl-meta {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
}
.acl-perm {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--ink3);
  background: var(--rule2);
  border: 1px solid var(--rule);
  padding: 2px 8px;
  border-radius: var(--r);
}
.acl-detail {
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
  margin-top: 8px;
  border-top: 1px solid var(--rule2);
  padding-top: 8px;
}
.acl-detail-item { font-size: 11px; color: var(--ink3); }
.acl-detail-item strong { color: var(--ink); font-weight: 500; }
.acl-ou-path {
  font-size: 10px;
  color: var(--ink4);
  font-style: italic;
  margin-top: 4px;
}

/* ── Score bar ───────────────────────────────────────── */
.score-wrap { display: flex; align-items: center; gap: 8px; }
.score-bar {
  height: 4px;
  border-radius: 2px;
  min-width: 4px;
  flex-shrink: 0;
}
.bar-critical { background: var(--red); }
.bar-high     { background: var(--amber); }
.bar-med      { background: var(--slate); }
.score-num {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--ink3);
  white-space: nowrap;
}

/* ── Heatmap ─────────────────────────────────────────── */
.heatmap-row { display: flex; flex-direction: column; gap: 1px; }
.heatmap-entry {
  background: var(--paper2);
  border: 1px solid var(--rule);
  padding: 12px 16px;
  display: grid;
  grid-template-columns: 1fr auto auto auto auto auto;
  gap: 16px;
  align-items: center;
}
.heatmap-entry.he-critical { border-left: 3px solid var(--red); }
.heatmap-entry.he-high     { border-left: 3px solid var(--amber); }
.hm-label { font-size: 12px; color: var(--ink2); }
.hm-label small { display: block; font-size: 10px; color: var(--ink4); }
.hm-stat { text-align: center; }
.hm-stat .n { font-family: var(--serif); font-size: 20px; font-weight: 700; }
.hm-stat .n.n-crit { color: var(--red); }
.hm-stat .n.n-high { color: var(--amber); }
.hm-stat small { display: block; font-size: 9px; color: var(--ink4); letter-spacing: 1px; text-transform: uppercase; }
.prox-pill {
  font-family: var(--mono);
  font-size: 9px;
  padding: 2px 6px;
  border-radius: var(--r);
  white-space: nowrap;
}
.prox-0  { background: var(--red-bg);   color: var(--red);   border: 1px solid rgba(192,57,43,.2); }
.prox-1  { background: var(--amber-bg); color: var(--amber); border: 1px solid rgba(180,83,9,.2);  }
.prox-2  { background: var(--slate-bg); color: var(--slate); border: 1px solid rgba(51,65,85,.2);  }
.prox-hi { background: var(--rule2);    color: var(--ink4);  border: 1px solid var(--rule);        }

/* ── Kerb / delegation cards ─────────────────────────── */
.info-card {
  background: var(--paper2);
  border: 1px solid var(--rule);
  padding: 14px 18px;
  margin-bottom: 1px;
}
.info-card-top { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.info-card-body {
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid var(--rule2);
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
  font-size: 11px;
  color: var(--ink3);
}
.info-card-body strong { color: var(--ink); font-weight: 500; }
.spn-list { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }
.spn {
  font-family: var(--mono);
  font-size: 10px;
  padding: 1px 6px;
  background: var(--rule2);
  border: 1px solid var(--rule);
  border-radius: var(--r);
  color: var(--ink3);
  word-break: break-all;
}

/* ── Graph explorer ──────────────────────────────────── */
#graph-wrap {
  border: 1px solid var(--rule);
  background: var(--paper2);
  position: relative;
  overflow: hidden;
  height: 560px;
  cursor: grab;
}
#graph-wrap:active { cursor: grabbing; }
#graph-svg { width: 100%; height: 100%; display: block; }

.graph-legend {
  display: flex;
  gap: 20px;
  flex-wrap: wrap;
  font-size: 11px;
  color: var(--ink3);
  margin-bottom: 10px;
}
.legend-item { display: flex; align-items: center; gap: 6px; }
.legend-dot  { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
.legend-sq   { width: 9px; height: 9px; border-radius: 1px; flex-shrink: 0; }

.graph-controls { display: flex; gap: 8px; margin-bottom: 10px; }
.gbtn {
  font-family: var(--mono);
  font-size: 10px;
  padding: 5px 12px;
  border: 1px solid var(--rule);
  background: var(--paper2);
  color: var(--ink3);
  cursor: pointer;
  border-radius: var(--r);
  letter-spacing: .5px;
}
.gbtn:hover { border-color: var(--ink); color: var(--ink); }

/* ── Tooltip ─────────────────────────────────────────── */
#tip {
  position: fixed;
  background: var(--ink);
  color: var(--paper);
  font-family: var(--mono);
  font-size: 11px;
  padding: 8px 12px;
  border-radius: var(--r);
  pointer-events: none;
  z-index: 9999;
  display: none;
  max-width: 340px;
  line-height: 1.6;
  box-shadow: 0 4px 20px rgba(0,0,0,.25);
}
#tip strong { color: #f0c040; display: block; }

/* ── Footer ──────────────────────────────────────────── */
footer {
  margin-top: 64px;
  padding-top: 18px;
  border-top: 1px solid var(--rule);
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 6px;
  font-size: 9px;
  color: var(--ink4);
  letter-spacing: 1.5px;
  text-transform: uppercase;
}

/* ── Animations ──────────────────────────────────────── */
@keyframes fadeUp {
  from { opacity: 0; transform: translateY(12px); }
  to   { opacity: 1; transform: translateY(0); }
}
.section {
  animation: fadeUp .4s ease both;
}
.section:nth-child(2)  { animation-delay: .04s; }
.section:nth-child(3)  { animation-delay: .08s; }
.section:nth-child(4)  { animation-delay: .12s; }
.section:nth-child(5)  { animation-delay: .16s; }
.section:nth-child(6)  { animation-delay: .20s; }
.section:nth-child(7)  { animation-delay: .24s; }
.section:nth-child(8)  { animation-delay: .28s; }

.score-num {display: none !important;}
.badge-low {display: none !important;}
"""


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def render_header(summary: Dict, metadata: Dict) -> str:
    domain      = esc(summary.get("domain", metadata.get("domain", "UNKNOWN")))
    coll_date   = esc(metadata.get("collection_date", "—"))
    refined_at  = esc(summary.get("refined_at", "—")[:19].replace("T", " "))
    generated   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""
<header>
  <div class="hdr-left">
    <span class="hdr-eyebrow">Authorization Intelligence &#x2022; Refined Analysis</span>
    <h1>AD Auth<em>Graph</em></h1>
  </div>
  <div class="hdr-right">
    <div class="hdr-domain">&#x25cf; {domain}</div>
    <div>Collection &nbsp; {coll_date}</div>
    <div>Refined &nbsp;&nbsp;&nbsp; {refined_at}</div>
    <div>Report &nbsp;&nbsp;&nbsp;&nbsp; {generated}</div>
  </div>
</header>"""


def render_summary(summary: Dict) -> str:
    def kpi(label: str, value: Any, sub: str = "", alert: bool = False, warn: bool = False) -> str:
        cls = " kpi-alert" if alert else " kpi-warn" if warn else ""
        return f"""<div class="kpi{cls}">
  <div class="kpi-label">{label}</div>
  <div class="kpi-value">{esc(value)}</div>
  <div class="kpi-sub">{sub}</div>
</div>"""

    total_acl   = summary.get("total_acl_findings", 0)
    pri_acl     = summary.get("high_priority_acl_findings", 0)
    avg_expl    = summary.get("avg_exploitability_score", 0.0)
    da_ids      = summary.get("identities_with_da_paths", 0)
    kerb        = summary.get("kerberoastable_identities", 0)
    pri_kerb    = summary.get("high_priority_kerberoastable", 0)
    deleg       = summary.get("delegation_risks", 0)
    reg_size    = summary.get("registry_size", 0)

    tiles = [
        kpi("ACL Abuse Chains",      total_acl,  "",                            alert=pri_acl > 0),
        kpi("DA Path Holders",       da_ids,     "identities → Domain Admins",  alert=da_ids > 0),
        kpi("Kerberoastable",        kerb,        "",                            warn=kerb > 0),
        kpi("Delegation Risks",      deleg,       "configured delegations",      warn=deleg > 0),
        kpi("Registry Size",         reg_size,    "AD objects tracked"),
    ]

    # Top exploitable chains mini-table
    top = summary.get("top_exploitable_chains", [])
    top_rows = ""
    for t in top:
        badge_cls = f"badge-{t.get('risk_level','low').lower()}"
        top_rows += f"""<tr>
  <td>{render_chip('User:' + t['source'], t['source'])}</td>
  <td>{render_chip('User:' + t['target'], t['target'])}</td>
  <td>{score_bar(t.get('exploitability_score', 0))}</td>
  <td><span class="badge {badge_cls}">{esc(t.get('risk_level',''))}</span></td>
</tr>"""

    top_table = ""
    if top_rows:
        top_table = f"""
<div style="margin-top:18px;">
  <div style="font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--ink4);margin-bottom:8px;">
    Top Exploitable Chains
  </div>
  <div class="tbl-wrap">
  <table>
    <thead><tr><th>Source</th><th>Target</th><th>Score</th><th>Risk</th></tr></thead>
    <tbody>{top_rows}</tbody>
  </table>
  </div>
</div>"""

    return f"""
<div class="section">
  <div class="section-hdr">
    <span class="section-title">Executive Summary</span>
  </div>
  <div class="kpi-row">{''.join(tiles)}</div>
  {top_table}
</div>"""


def render_acl_chains(findings: List[Dict]) -> str:
    if not findings:
        return f"""
<div class="section">
  <div class="section-hdr">
    <span class="section-title">ACL Abuse Chains</span>
    <span class="section-count">0 findings</span>
  </div>
  <div style="color:var(--ink4);font-size:12px;padding:16px 0">No ACL abuse chains detected.</div>
</div>"""

    cards = ""
    for f in findings:
        risk      = f.get("risk_level", "LOW")
        r_cls     = risk.lower()
        p_flag    = f.get("priority_flag", False)
        card_cls  = f"acl-card priority-{r_cls}" if p_flag else "acl-card"

        src        = f.get("source", {})
        tgt        = f.get("target", {})
        chain_data = f.get("escalation_chain", {})
        chain_nodes= chain_data.get("nodes", [src.get("node_id",""), tgt.get("node_id","")])
        chain_len  = chain_data.get("length", len(chain_nodes))
        expl       = f.get("exploitability_score", 0.0)
        acl        = f.get("acl", {})
        perm_raw   = esc(acl.get("full_permission") or acl.get("edge_type", ""))
        ou_dir     = esc(acl.get("acl_path_direction", ""))
        auth_gained= f.get("authorities_gained", [])
        explanation= esc(chain_data.get("explanation", ""))

        src_prox = src.get("privilege_proximity")
        tgt_prox = tgt.get("privilege_proximity")

        src_prox_txt = f"prox: {src_prox}" if src_prox is not None else "no path"
        tgt_prox_txt = f"prox: {tgt_prox}" if tgt_prox is not None else "no path"

        badge_cls = f"badge badge-{r_cls}"

        auth_html = ""
        if auth_gained:
            auth_chips = " ".join(
                render_chip(a, sam(a) if ":" in a else a)
                for a in auth_gained[:6]
            )
            auth_html = f'<div class="acl-detail-item"><strong>Authorities Gained:</strong> {auth_chips}</div>'

        cards += f"""
<div class="{card_cls}">
  <div class="acl-top">
    <div class="acl-chain-row">
      {render_path_chips(chain_nodes)}
    </div>
    <div class="acl-meta">
      {score_bar(expl)}
      <span class="{badge_cls}">{risk}</span>
    </div>
  </div>
  <div class="acl-ou-path">{ou_dir}</div>
  <div class="acl-detail">
    <div class="acl-detail-item"><strong>Permission:</strong> <span class="acl-perm">{perm_raw}</span></div>
    <div class="acl-detail-item"><strong>Chain:</strong> {chain_len} hops</div>
    <div class="acl-detail-item"><strong>Source Proximity:</strong> {src_prox_txt}</div>
    <div class="acl-detail-item"><strong>Target Proximity:</strong> {tgt_prox_txt}</div>
    {auth_html}
  </div>
  {'<div class="acl-detail-item" style="margin-top:6px;font-size:11px;color:var(--ink3)">' + explanation + '</div>' if explanation else ''}
</div>"""

    pri_count = sum(1 for f in findings if f.get("priority_flag"))

    return f"""
<div class="section">
  <div class="section-hdr">
    <span class="section-title">ACL Abuse Chains</span>
    <span class="section-count">{len(findings)} findings &nbsp;·&nbsp; {pri_count} high-priority</span>
  </div>
  <div class="acl-cards">{cards}</div>
</div>"""


def render_ou_heatmap(heatmap: List[Dict]) -> str:
    
        return ""

def render_da_paths(da_entries: List[Dict]) -> str:
    if not da_entries:
        return f"""
<div class="section">
  <div class="section-hdr">
    <span class="section-title">Domain Admin Privilege Paths</span>
    <span class="section-count">0</span>
  </div>
  <div style="color:var(--ink4);font-size:12px;padding:16px 0">No DA escalation paths found.</div>
</div>"""

    rows = ""
    for e in da_entries:
        node_id  = e.get("node_id", "")
        s_prox   = e.get("privilege_proximity")
        prox_txt = str(s_prox) if s_prox is not None else "—"
        path     = e.get("shortest_path", [])
        ou_lbl   = esc(e.get("ou_path_label", ""))
        path_cnt = e.get("path_count", 1)
        shortest = e.get("shortest_path_length", len(path))
        agree    = e.get("proximity_analysis_agreement", True)
        agree_mk = "✓" if agree else "△"

        rows += f"""<tr>
  <td>{render_chip(node_id)}</td>
  <td>{render_path_chips(path)}</td>
  <td style="text-align:center">{path_cnt}</td>
  <td style="text-align:center">{shortest}</td>
  <td style="text-align:center">{prox_txt}</td>
  <td style="color:var(--ink4);font-size:10px">{ou_lbl}</td>
  <td style="text-align:center;color:var(--ink4)">{agree_mk}</td>
</tr>"""

    return f"""
<div class="section">
  <div class="section-hdr">
    <span class="section-title">Domain Admin Privilege Paths</span>
    <span class="section-count">{len(da_entries)} identities</span>
  </div>
  <div class="tbl-wrap">
  <table>
    <thead>
      <tr>
        <th>Identity</th><th>Shortest Path</th><th>Paths</th>
        <th>Hops</th><th>Prox</th><th>OU</th><th>BFS</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
  </div>
</div>"""


def render_kerberoastable(kerb_entries: List[Dict]) -> str:
    if not kerb_entries:
        return f"""
<div class="section">
  <div class="section-hdr">
    <span class="section-title">Kerberoastable Identities</span>
    <span class="section-count">0</span>
  </div>
  <div style="color:var(--ink4);font-size:12px;padding:16px 0">No Kerberoastable identities found.</div>
</div>"""

    cards = ""
    for e in kerb_entries:
        node_id  = e.get("node_id", "")
        risk     = e.get("risk_level", "MEDIUM")
        r_cls    = risk.lower()
        badge_c  = f"badge badge-{r_cls}"
        spns     = e.get("spns", [])
        paths_da = e.get("paths_to_da", 0)
        prox     = e.get("privilege_proximity")
        prox_txt = str(prox) if prox is not None else "—"
        ou_lbl   = esc(e.get("ou_path_label", ""))
        enabled  = e.get("enabled", True)
        p_flag   = e.get("priority_flag", False)

        da_badge = (
            f'<span class="badge badge-critical">DA PATH</span>'
            if paths_da > 0 else
            '<span class="badge badge-low">NO DA PATH</span>'
        )
        enabled_txt = "ENABLED" if enabled else '<span style="color:var(--ink4)">DISABLED</span>'

        spn_chips = "".join(f'<span class="spn">{esc(s)}</span>' for s in spns)

        border_style = "border-left:3px solid var(--red)" if p_flag else ""

        cards += f"""
<div class="info-card" style="{border_style}">
  <div class="info-card-top">
    {render_chip(node_id)}
    <span class="{badge_c}">{risk}</span>
    {da_badge}
    <span style="font-size:10px;color:var(--ink4)">{enabled_txt}</span>
    <span style="font-size:10px;color:var(--ink4);margin-left:auto">prox: {prox_txt}</span>
  </div>
  <div class="spn-list">{spn_chips}</div>
  <div class="info-card-body" style="margin-top:6px">
    <span><strong>OU:</strong> {ou_lbl}</span>
    <span><strong>SPN Count:</strong> {len(spns)}</span>
    <span><strong>DA Paths:</strong> {paths_da}</span>
  </div>
</div>"""

    pri_count = sum(1 for e in kerb_entries if e.get("priority_flag"))

    return f"""
<div class="section">
  <div class="section-hdr">
    <span class="section-title">Kerberoastable Identities</span>
    <span class="section-count">{len(kerb_entries)} identities &nbsp;·&nbsp; {pri_count} high-priority</span>
  </div>
  {cards}
</div>"""


def render_delegation(delegation_entries: List[Dict]) -> str:
    if not delegation_entries:
        return f"""
<div class="section">
  <div class="section-hdr">
    <span class="section-title">Delegation Risks</span>
    <span class="section-count">0</span>
  </div>
  <div style="color:var(--ink4);font-size:12px;padding:16px 0">No delegation risks found.</div>
</div>"""

    cards = ""
    for e in delegation_entries:
        src      = e.get("source", {})
        tgt      = e.get("target", {})
        dtype    = esc(e.get("delegation_type", ""))
        risk     = e.get("risk_level", "MEDIUM")
        r_cls    = risk.lower()
        conds    = e.get("conditions", [])
        cond_txt = ", ".join(esc(c) for c in conds) if conds else "none"
        ou_dir   = esc(e.get("acl_path_direction", ""))
        p_flag   = e.get("priority_flag", False)

        border_style = "border-left:3px solid var(--amber)" if p_flag else ""

        cards += f"""
<div class="info-card" style="{border_style}">
  <div class="info-card-top">
    {render_chip(src.get("node_id",""), src.get("sam",""))}
    <span class="arr">→</span>
    {render_chip(tgt.get("node_id",""), tgt.get("sam",""))}
    <span class="badge badge-{r_cls}">{risk}</span>
    <span style="font-family:var(--mono);font-size:10px;background:var(--rule2);border:1px solid var(--rule);padding:2px 8px;border-radius:var(--r)">{dtype}</span>
  </div>
  <div class="info-card-body">
    <span><strong>Conditions:</strong> {cond_txt}</span>
    <span><strong>OU Direction:</strong> {ou_dir}</span>
    <span><strong>Source Prox:</strong> {src.get("privilege_proximity","—")}</span>
  </div>
</div>"""

    return f"""
<div class="section">
  <div class="section-hdr">
    <span class="section-title">Delegation Risks</span>
    <span class="section-count">{len(delegation_entries)}</span>
  </div>
  {cards}
</div>"""


def render_graph_explorer(refined: Dict) -> str:
    """
    Build the force-directed graph explorer from refined JSON.

    Nodes: all identities referenced across findings.
    Edges: ACL abuse chains (colored by risk) + DA path membership edges.
    Uses .replace() injection — no .format() on JS templates.
    """

    # ── Collect nodes ──────────────────────────────────────────────────
    nodes_map: Dict[str, Dict] = {}

    def ensure_node(node_id: str, node_type: str = "", sam_name: str = "") -> None:
        if not node_id or node_id in nodes_map:
            return
        nodes_map[node_id] = {
            "id":        node_id,
            "node_type": node_type or (node_id.split(":")[0].lower() if ":" in node_id else "other"),
            "label":     sam_name or (node_id.split(":", 1)[1] if ":" in node_id else node_id),
        }

    def add_from_ctx(ctx: Dict) -> None:
        if ctx:
            ensure_node(ctx.get("node_id",""), ctx.get("node_type",""), ctx.get("sam",""))

    acl_findings    = [
        f for f in refined.get("high_risk_ou_acl_paths",[])
        if f.get("priority_flag")
    ]

    acl_findings = sorted(
        acl_findings,
        key=lambda x: x.get("exploitability_score", 0),
        reverse=True
    )[:200]
    da_entries      = refined.get("da_path_ou_map", [])
    kerb_entries    = refined.get("kerberoastable_ou_map", [])
    deleg_entries   = refined.get("delegation_ou_map", [])

    graph_edges = []  # {source, target, risk, label}

    for f in acl_findings:
        add_from_ctx(f.get("source", {}))
        add_from_ctx(f.get("target", {}))
        chain_nodes = f.get("escalation_chain", {}).get("nodes", [])
        if not chain_nodes or len(chain_nodes) < 2:
            continue
        for n in chain_nodes:
            ensure_node(n)
        # Add escalation chain edges
        risk = f.get("risk_level", "LOW")
        for i in range(len(chain_nodes) - 1):
            graph_edges.append({
                "source": chain_nodes[i],
                "target": chain_nodes[i + 1],
                "risk":   risk,
                "label":  f.get("acl", {}).get("edge_type", "acl"),
            })

    for e in da_entries:
        ensure_node(e.get("node_id",""), e.get("node_type",""), e.get("sam",""))
        path = e.get("shortest_path", [])
        for i in range(len(path) - 1):
            ensure_node(path[i])
            ensure_node(path[i+1])
            graph_edges.append({
                "source": path[i],
                "target": path[i + 1],
                "risk":   "membership",
                "label":  "member_of",
            })

    for e in kerb_entries:
        add_from_ctx(e)

    for e in deleg_entries:
        add_from_ctx(e.get("source", {}))
        add_from_ctx(e.get("target", {}))
        graph_edges.append({
            "source": e.get("source", {}).get("node_id", ""),
            "target": e.get("target", {}).get("node_id", ""),
            "risk":   e.get("risk_level", "MEDIUM"),
            "label":  "delegation",
        })

    # Deduplicate edges
    seen_edges = set()
    unique_edges = []
    for edge in graph_edges:
        key = (edge["source"], edge["target"], edge["label"])
        if key not in seen_edges and edge["source"] and edge["target"]:
            seen_edges.add(key)
            unique_edges.append(edge)

    graph_json_str = json.dumps({
        "nodes": list(nodes_map.values()),
        "edges": unique_edges,
    })

    # ── Build JS (NO .format() — use template with GRAPH_JSON_PLACEHOLDER) ──
    js_template = r"""
(function() {
  var raw = GRAPH_JSON_PLACEHOLDER;
  if (!raw || !raw.nodes || raw.nodes.length === 0) return;

  var svg  = document.getElementById('graph-svg');
  var wrap = document.getElementById('graph-wrap');
  if (!svg || !wrap) return;
  var W = wrap.clientWidth  || 1000;
  var H = wrap.clientHeight || 560;

  var nodeColor = {
    user:     '#0e0e0e',
    group:    '#c0392b',
    computer: '#b45309',
    spn:      '#334155',
    other:    '#909090'
  };
  var edgeColor = {
    CRITICAL:   '#c0392b',
    HIGH:       '#b45309',
    MEDIUM:     '#334155',
    LOW:        '#909090',
    membership: '#d8d8d8',
    delegation: '#b45309'
  };

  // ── Init node positions ──────────────────────────────────────
  var nodes = raw.nodes.map(function(n) {
    return {
      id:    n.id,
      type:  n.node_type || 'other',
      label: n.label || n.id,
      x:     W/2 + (Math.random()-0.5)*W*0.65,
      y:     H/2 + (Math.random()-0.5)*H*0.65,
      vx: 0, vy: 0
    };
  });

  var nodeMap = {};
  nodes.forEach(function(n) { nodeMap[n.id] = n; });

  var links = raw.edges
    .filter(function(e) { return nodeMap[e.source] && nodeMap[e.target]; })
    .map(function(e) {
      return {s: nodeMap[e.source], t: nodeMap[e.target], risk: e.risk, label: e.label};
    });

  // ── Build SVG ────────────────────────────────────────────────
  var NS = 'http://www.w3.org/2000/svg';
  function el(tag, attrs) {
    var e = document.createElementNS(NS, tag);
    for (var k in (attrs||{})) e.setAttribute(k, attrs[k]);
    return e;
  }

  var defs = el('defs');
  var mkr  = el('marker', {id:'arr', markerWidth:'8', markerHeight:'6',
    refX:'14', refY:'3', orient:'auto'});
  mkr.appendChild(el('polygon', {points:'0 0,8 3,0 6', fill:'#d8d8d8'}));
  defs.appendChild(mkr); svg.appendChild(defs);

  var gLinks = el('g'); svg.appendChild(gLinks);
  var gNodes = el('g'); svg.appendChild(gNodes);

  var tip = document.getElementById('tip');
  function showTip(e, html) {
    tip.innerHTML = html; tip.style.display='block';
    var x = e.clientX+14, y = e.clientY+14;
    if (x+360>window.innerWidth)  x = e.clientX-360;
    if (y+160>window.innerHeight) y = e.clientY-160;
    tip.style.left=x+'px'; tip.style.top=y+'px';
  }
  function hideTip() { tip.style.display='none'; }
  document.addEventListener('mousemove', function(e) {
    if (tip.style.display!=='none') {
      var x=e.clientX+14, y=e.clientY+14;
      if (x+360>window.innerWidth)  x=e.clientX-360;
      if (y+160>window.innerHeight) y=e.clientY-160;
      tip.style.left=x+'px'; tip.style.top=y+'px';
    }
  });

  var lineEls = links.map(function(lk) {
    var col = edgeColor[lk.risk] || '#d8d8d8';
    var line = el('line', {stroke:col, 'stroke-width':'1.5',
      'marker-end':'url(#arr)', opacity:'0.7'});
    gLinks.appendChild(line);
    line.addEventListener('mouseenter', function(e) {
      showTip(e, '<strong>' + lk.label + '</strong>' + lk.s.label + ' → ' + lk.t.label);
    });
    line.addEventListener('mouseleave', hideTip);
    return line;
  });

  var nodeEls = nodes.map(function(n) {
    var g = el('g', {cursor:'pointer'});
    var col = nodeColor[n.type] || '#909090';
    var r = n.type==='group' ? 9 : 7;
    var shape;
    if (n.type === 'group') {
      shape = el('rect', {x:-r, y:-r, width:r*2, height:r*2,
        rx:'2', fill:col, opacity:'0.9'});
    } else {
      shape = el('circle', {r:r, fill:col, opacity:'0.9'});
    }
    var lbl = el('text', {'text-anchor':'middle', dy:'18',
      fill:'#909090', 'font-size':'9',
      'font-family':'DM Mono, monospace', 'pointer-events':'none'});
    lbl.textContent = n.label.length>18 ? n.label.slice(0,16)+'..' : n.label;
    g.appendChild(shape); g.appendChild(lbl);
    gNodes.appendChild(g);

    g.addEventListener('mouseenter', function(e) {
      shape.setAttribute('opacity','1');
      showTip(e, '<strong>' + n.id + '</strong>Type: ' + n.type);
    });
    g.addEventListener('mouseleave', function() {
      shape.setAttribute('opacity','0.9'); hideTip();
    });

    var dragging=false, ox=0, oy=0;
    g.addEventListener('mousedown', function(e) {
      dragging=true; ox=e.clientX-n.x; oy=e.clientY-n.y; e.preventDefault();
    });
    window.addEventListener('mousemove', function(e) {
      if (!dragging) return;
      n.x=e.clientX-ox; n.y=e.clientY-oy; n.vx=0; n.vy=0;
    });
    window.addEventListener('mouseup', function() { dragging=false; });
    return {g:g, shape:shape, n:n};
  });

  // ── Force simulation ─────────────────────────────────────────
  function tick() {
    var repulsion=900, attraction=0.04, damping=0.85;
    for (var i=0; i<nodes.length; i++) {
      for (var j=i+1; j<nodes.length; j++) {
        var a=nodes[i], b=nodes[j];
        var dx=b.x-a.x, dy=b.y-a.y;
        var d=Math.max(Math.sqrt(dx*dx+dy*dy),1);
        var f=repulsion/(d*d);
        a.vx-=f*dx; a.vy-=f*dy; b.vx+=f*dx; b.vy+=f*dy;
      }
    }
    links.forEach(function(lk) {
      var dx=lk.t.x-lk.s.x, dy=lk.t.y-lk.s.y;
      var d=Math.sqrt(dx*dx+dy*dy)||1;
      var f=(d-90)*attraction;
      lk.s.vx+=f*dx/d; lk.s.vy+=f*dy/d;
      lk.t.vx-=f*dx/d; lk.t.vy-=f*dy/d;
    });
    nodes.forEach(function(n) {
      n.vx+=(W/2-n.x)*0.002; n.vy+=(H/2-n.y)*0.002;
      n.vx*=damping; n.vy*=damping;
      n.x+=n.vx; n.y+=n.vy;
      n.x=Math.max(18, Math.min(W-18, n.x));
      n.y=Math.max(18, Math.min(H-18, n.y));
    });
    for (var i=0; i<links.length; i++) {
      lineEls[i].setAttribute('x1', links[i].s.x);
      lineEls[i].setAttribute('y1', links[i].s.y);
      lineEls[i].setAttribute('x2', links[i].t.x);
      lineEls[i].setAttribute('y2', links[i].t.y);
    }
    nodeEls.forEach(function(ne) {
      ne.g.setAttribute('transform','translate('+ne.n.x+','+ne.n.y+')');
    });
    requestAnimationFrame(tick);
  }
  tick();

  // ── Pan / zoom ───────────────────────────────────────────────
  var panX=0, panY=0, zoom=1, panning=false, px=0, py=0;
  wrap.addEventListener('mousedown', function(e) {
    if (e.target===svg||e.target===wrap) {panning=true; px=e.clientX; py=e.clientY;}
  });
  window.addEventListener('mousemove', function(e) {
    if (!panning) return;
    panX+=e.clientX-px; panY+=e.clientY-py; px=e.clientX; py=e.clientY;
    svg.style.transform='translate('+panX+'px,'+panY+'px) scale('+zoom+')';
  });
  window.addEventListener('mouseup', function() { panning=false; });
  wrap.addEventListener('wheel', function(e) {
    e.preventDefault();
    zoom=Math.max(.3,Math.min(3, zoom-e.deltaY*0.001));
    svg.style.transform='translate('+panX+'px,'+panY+'px) scale('+zoom+')';
  }, {passive:false});

  document.getElementById('gbtn-reset').addEventListener('click', function() {
    panX=0; panY=0; zoom=1; svg.style.transform='';
  });
})();
"""

    js_final = js_template.replace("GRAPH_JSON_PLACEHOLDER", graph_json_str)

    n_count = len(nodes_map)
    e_count = len(unique_edges)

    return f"""
<div class="section">
  <div class="section-hdr">
    <span class="section-title">Graph Explorer</span>
    <span class="section-count">{n_count} nodes &nbsp;·&nbsp; {e_count} edges</span>
  </div>
  <div class="graph-legend">
    <div class="legend-item"><div class="legend-dot" style="background:#0e0e0e"></div> User</div>
    <div class="legend-item"><div class="legend-sq" style="background:#c0392b"></div> Group</div>
    <div class="legend-item"><div class="legend-dot" style="background:#b45309"></div> Computer</div>
    <div class="legend-item"><div class="legend-dot" style="background:#334155"></div> SPN</div>
    <div class="legend-item"><div style="width:18px;height:2px;background:#c0392b;margin-top:4px"></div>&nbsp;Critical ACL</div>
    <div class="legend-item"><div style="width:18px;height:2px;background:#d8d8d8;margin-top:4px"></div>&nbsp;Membership</div>
  </div>
  <div class="graph-controls">
    <button class="gbtn" id="gbtn-reset">&#x21ba; Reset View</button>
    <span style="font-size:10px;color:var(--ink4);padding:5px 0">
      Drag nodes &nbsp;·&nbsp; Scroll to zoom &nbsp;·&nbsp; Pan on canvas &nbsp;·&nbsp; Hover for details
    </span>
  </div>
  <div id="graph-wrap">
    <svg id="graph-svg" xmlns="http://www.w3.org/2000/svg"
         style="transform-origin:0 0"></svg>
  </div>
</div>
<script>{js_final}</script>"""


# ---------------------------------------------------------------------------
# Full HTML assembler
# ---------------------------------------------------------------------------

def build_report(refined_path: str) -> str:
    with open(refined_path, "r", encoding="utf-8-sig") as f:
        refined: Dict = json.load(f)

    summary    = refined.get("summary", {})
    metadata   = refined.get("metadata", {})
    acl        = refined.get("high_risk_ou_acl_paths", [])
    heatmap    = refined.get("ou_risk_heatmap", [])
    da_entries = refined.get("da_path_ou_map", [])
    kerb       = refined.get("kerberoastable_ou_map", [])
    deleg      = refined.get("delegation_ou_map", [])

    domain     = esc(summary.get("domain", metadata.get("domain", "UNKNOWN")))
    generated  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_parts = [
        f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD AuthGraph Refined — {domain}</title>
<style>{CSS}</style>
</head>
<body>
<div id="tip"></div>
<div class="page">""",

        render_header(summary, metadata),
        render_summary(summary),
        render_acl_chains(acl),
        render_ou_heatmap(heatmap),
        render_da_paths(da_entries),
        render_kerberoastable(kerb),
        render_delegation(deleg),
        render_graph_explorer(refined),

        f"""
<footer>
  <span>AD Authorization Refined Report &nbsp;·&nbsp; Siddharth Ray Chaudhuri</span>
  <span>Generated {esc(generated)}</span>
</footer>
</div>
</body>
</html>""",
    ]

    return "\n".join(html_parts)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 80)
    print("Authorization Refined Report Visualizer")
    print("=" * 80)
    print()

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage:")
        print("  python visualizer_refined.py <refined_json> [--output <path>]")
        print()
        print("  refined_json   ad_authorization_state_refined.json  (required)")
        print("  --output       Output HTML path (default: <stem>_report_refined.html)")
        print()
        print("Pipeline position:")
        print("  refiner.py -> ad_authorization_state_refined.json")
        print("  visualizer_refined.py -> ad_authorization_state_report_refined.html")
        sys.exit(0)

    refined_file = sys.argv[1]
    output_file: Optional[str] = None

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--output" and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    if not output_file:
        stem = Path(refined_file).stem
        # Remove _refined suffix if present, add _report_refined
        base = stem.replace("_refined", "")
        output_file = base + "_report_refined.html"

    if not Path(refined_file).exists():
        print(f"[-] Error: Refined JSON not found: {refined_file}")
        sys.exit(1)

    print(f"[*] Loading refined data: {refined_file}")
    html_content = build_report(refined_file)

    output_path = Path(output_file)
    output_path.write_text(html_content, encoding="utf-8")

    size_kb = output_path.stat().st_size / 1024
    print(f"[+] Report written: {output_path}")
    print(f"    Size: {size_kb:.1f} KB")
    print()
    print("[✓] Visualization complete!")
    print(f"    Open in browser: file:///{output_path.resolve()}")


if __name__ == "__main__":
    main()