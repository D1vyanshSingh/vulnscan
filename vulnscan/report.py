"""Report generation: JSON (machine), HTML (human), terminal (operator)."""

from __future__ import annotations

import html
import json
import time
from datetime import datetime, timezone

from . import __version__
from .checks import SEVERITY_ORDER, Finding
from .scanner import PortService

REPORT_SCHEMA_VERSION = "1.0"

SEV_META = {
    "critical":     {"label": "Critical",     "hex": "#7F1D1D", "wash": "#FBE9EB"},
    "high":         {"label": "High",         "hex": "#B42318", "wash": "#FDECEA"},
    "medium":       {"label": "Medium",       "hex": "#B54708", "wash": "#FEF3E2"},
    "low":          {"label": "Low",          "hex": "#175CD3", "wash": "#EAF1FE"},
    "informational": {"label": "Informational", "hex": "#475467", "wash": "#F1F3F5"},
}
ANSI = {
    "critical": "\033[1;95m", "high": "\033[1;91m", "medium": "\033[1;93m",
    "low": "\033[1;96m", "informational": "\033[1;37m",
}
ANSI_RESET = "\033[0m"


def build_report(targets: list[str], ports: list[int], services: list[PortService],
                 findings: list[Finding], started_at: str, duration_s: float,
                 options: dict | None = None) -> dict:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {
        "report_version": REPORT_SCHEMA_VERSION,
        "metadata": {
            "title": "Vulnerability Scan Report",
            "scanner": {"name": "vulnscan", "version": __version__},
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "started_at": started_at,
            "duration_seconds": round(duration_s, 2),
        },
        "scope": {
            "targets": targets,
            "ports_scanned": len(ports),
            "port_range": _describe_ports(ports),
            "method": "async TCP connect scan with banner, TLS and HTTP probing",
            "options": options or {},
        },
        "summary": {
            "total_findings": len(findings),
            "counts_by_severity": counts,
            "open_services": len(services),
        },
        "services": [_service_dict(s) for s in services],
        "findings": [_finding_dict(f) for f in findings],
    }


def _describe_ports(ports: list[int]) -> str:
    if not ports:
        return ""
    ranges, start, prev = [], ports[0], ports[0]
    for port in ports[1:]:
        if port == prev + 1:
            prev = port
            continue
        ranges.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = port
    ranges.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(ranges[:40]) + (", …" if len(ranges) > 40 else "")


def _service_dict(svc: PortService) -> dict:
    out = {
        "host": svc.host, "ip": svc.ip, "port": svc.port, "state": svc.state,
        "service": svc.service, "product": svc.product, "version": svc.version,
        "banner": svc.banner[:512],
    }
    if svc.tls:
        out["tls"] = svc.tls
    if svc.http:
        http = dict(svc.http)
        http["body_preview"] = http.get("body_preview", "")[:1000]
        out["http"] = http
    return out


def _finding_dict(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "status": finding.status,
        "cwe": finding.cwe,
        "cve": finding.cve,
        "asset": finding.asset,
        "description": finding.description,
        "impact": finding.impact,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "references": finding.references,
        "next_steps": finding.next_steps,
        "provenance": {"scanner": f"vulnscan {__version__}"},
    }


def write_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------

_CSS = """
:root {
  --ink: #14161a;
  --ink-soft: #4a515c;
  --line: #dfe3e8;
  --paper: #ffffff;
  --desk: #eceef1;
  --accent: #7f1d1d;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--desk); color: var(--ink);
  font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
  font-size: 15px; line-height: 1.55;
}
.sheet {
  max-width: 60rem; margin: 0 auto; background: var(--paper);
  border-left: 1px solid var(--line); border-right: 1px solid var(--line);
  padding: 3rem 3.5rem 4rem;
}
.masthead { border-bottom: 2px solid var(--ink); padding-bottom: 1.25rem; }
.masthead h1 {
  font-family: "Iowan Old Style", Palatino, Georgia, serif;
  font-size: 2.1rem; font-weight: 600; margin: 0 0 .75rem;
  letter-spacing: -0.01em;
}
.meta {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
  gap: .4rem 2rem; margin: 0; font-size: .85rem;
}
.meta div { display: flex; flex-direction: column; }
.meta dt { color: var(--ink-soft); font-size: .74rem; margin-bottom: .1rem; }
.meta dd { margin: 0; font-variant-numeric: tabular-nums; }
h2 {
  font-family: "Iowan Old Style", Palatino, Georgia, serif;
  font-size: 1.35rem; font-weight: 600; margin: 2.75rem 0 1rem;
  padding-bottom: .4rem; border-bottom: 1px solid var(--line);
}
h3 { font-size: .98rem; font-weight: 650; margin: 0 0 .35rem; }

.riskbar { display: flex; height: 1.4rem; border-radius: 3px; overflow: hidden;
  background: var(--desk); margin-bottom: .9rem; }
.riskbar span { display: block; height: 100%; }
.riskcounts { display: flex; flex-wrap: wrap; gap: .45rem; margin-bottom: .4rem; }
.riskcounts button {
  font: inherit; font-size: .8rem; border: 1px solid var(--line);
  background: #fff; border-radius: 4px; padding: .22rem .6rem; cursor: pointer;
  display: flex; align-items: baseline; gap: .4rem; color: var(--ink);
}
.riskcounts button[aria-pressed="true"] { border-color: var(--ink); background: #f6f7f9; }
.riskcounts button:focus-visible { outline: 2px solid #175cd3; outline-offset: 2px; }
.riskcounts b { font-variant-numeric: tabular-nums; font-size: 1rem; }
.riskcounts .dot { width: .55rem; height: .55rem; border-radius: 50%; display: inline-block; }
.total { color: var(--ink-soft); font-size: .85rem; margin: .6rem 0 0; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.count-table td:first-child { font-size: .93rem; }

.finding { border: 1px solid var(--line); border-left-width: 5px; margin: 0 0 1.1rem; }
.finding-head { padding: .8rem 1rem .1rem; }
.finding h3 { font-size: 1.02rem; }
.finding dl { margin: .6rem 0 0; padding: 0 1rem 1rem; }
.finding dt {
  font-size: .74rem; color: var(--ink-soft); margin-top: .7rem;
}
.finding dd { margin: .1rem 0 0; }
.sev {
  display: inline-block; font-size: .72rem; font-weight: 650;
  padding: .1rem .5rem; border-radius: 999px; vertical-align: middle;
}
.fid { font-variant-numeric: tabular-nums; color: var(--ink-soft);
  font-size: .8rem; margin-right: .5rem; }
.tags { display: flex; flex-wrap: wrap; gap: .35rem; margin-top: .35rem; }
.tag {
  font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: .74rem;
  background: #f4f5f7; border: 1px solid var(--line); border-radius: 4px;
  padding: .05rem .4rem;
}
pre {
  font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: .78rem;
  background: #f7f8fa; border: 1px solid var(--line); border-radius: 4px;
  padding: .6rem .7rem; overflow-x: auto; white-space: pre-wrap;
  word-break: break-word; max-height: 14rem;
}
table { width: 100%; border-collapse: collapse; font-size: .85rem; }
th, td { text-align: left; padding: .42rem .6rem; border-bottom: 1px solid var(--line); }
th { font-weight: 600; background: #f7f8fa; }
td.mono, .mono { font-family: ui-monospace, "SF Mono", Consolas, monospace; }
.empty { color: var(--ink-soft); padding: 1rem 0; }
.prose { max-width: 44rem; color: var(--ink-soft); font-size: .9rem; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line);
  font-size: .78rem; color: var(--ink-soft); }
@media (max-width: 640px) {
  .sheet { padding: 1.5rem 1.1rem 3rem; border: 0; }
  .meta { grid-template-columns: 1fr 1fr; }
}
@media print {
  body { background: #fff; }
  .sheet { max-width: none; border: 0; padding: 0; }
  .finding { break-inside: avoid; }
  .riskcounts button { display: none; }
}
"""


def render_html(report: dict) -> str:
    meta = report["metadata"]
    scope = report["scope"]
    summary = report["summary"]
    counts = summary["counts_by_severity"]
    findings = report["findings"]
    services = report["services"]
    total = max(summary["total_findings"], 1)
    e = html.escape

    segments = "".join(
        f'<span style="width:{counts[sev] / total * 100:.2f}%;'
        f'background:{SEV_META[sev]["hex"]}" title="{SEV_META[sev]["label"]}"></span>'
        for sev in SEVERITY_ORDER if counts[sev])
    chips = "".join(
        f'<button type="button" data-sev="{sev}" aria-pressed="false">'
        f'<span class="dot" style="background:{SEV_META[sev]["hex"]}"></span>'
        f'{SEV_META[sev]["label"]} <b>{counts[sev]}</b></button>'
        for sev in SEVERITY_ORDER)

    findings_by_sev: dict[str, list] = {sev: [] for sev in SEVERITY_ORDER}
    for finding in findings:
        findings_by_sev.setdefault(finding["severity"], []).append(finding)

    # Prioritized remediation: one action per rule, ranked by how many
    # findings it clears (mirrors the reference report's Remediation table).
    by_rule: dict[str, list] = {}
    for finding in findings:
        by_rule.setdefault(finding["rule_id"], []).append(finding)
    remediation_rows = sorted(
        by_rule.items(),
        key=lambda kv: (-len(kv[1]), SEVERITY_ORDER.index(kv[1][0]["severity"])
                        if kv[1][0]["severity"] in SEVERITY_ORDER else 99))

    finding_blocks = "".join(_render_finding(f) for f in findings) or (
        '<p class="empty">No vulnerabilities matched the scan checks. '
        'Review the services table below — an empty result is not a guarantee '
        'of a clean system.</p>')

    severity_sections = "".join(_render_severity_section(sev, group)
                                for sev, group in findings_by_sev.items() if group)

    remed_html = "".join(
        "<tr>"
        f'<td>{e(fs[0]["remediation"])}</td>'
        f'<td style="color:{SEV_META[fs[0]["severity"]]["hex"]};font-weight:600">'
        f'{SEV_META[fs[0]["severity"]]["label"]}</td>'
        f'<td class="num">{len(fs)}</td>'
        f'<td class="num">{len({(a["asset"].get("host"), a["asset"].get("port")) for a in fs})}</td>'
        "</tr>"
        for _rule_id, fs in remediation_rows[:20])

    rows = "".join(
        "<tr>"
        f'<td class="mono">{e(s["host"])}</td>'
        f'<td class="mono">{s["port"]}</td>'
        f'<td class="mono">{e(s["service"] or "unknown")}</td>'
        f'<td>{e(s["product"] or "—")} {e(s["version"])}</td>'
        f'<td>{"TLS " + e(s["tls"].get("version", "")) if s.get("tls", {}).get("ok") else "—"}</td>'
        f'<td class="mono">{e((s.get("banner") or "")[:60])}</td>'
        "</tr>"
        for s in services) or '<tr><td colspan="6">No open ports found.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(meta["title"])} — {e(", ".join(scope["targets"]))}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="sheet">
  <header class="masthead">
    <h1>{e(meta["title"])}</h1>
    <dl class="meta">
      <div><dt>Target</dt><dd class="mono">{e(", ".join(scope["targets"]))}</dd></div>
      <div><dt>Generated</dt><dd>{e(meta["generated_at"])}</dd></div>
      <div><dt>Ports scanned</dt><dd>{scope["ports_scanned"]}
        <span class="mono" style="font-size:.8em">({e(scope["port_range"])})</span></dd></div>
      <div><dt>Open services</dt><dd>{summary["open_services"]}</dd></div>
      <div><dt>Duration</dt><dd>{meta["duration_seconds"]} s</dd></div>
      <div><dt>Scanner</dt><dd>{e(meta["scanner"]["name"])}
        {e(meta["scanner"]["version"])}</dd></div>
    </dl>
  </header>

  <h2 id="executive-summary">1. Executive summary</h2>
  <p class="prose">The purpose of this scan was to assess exposed network services
    on the listed targets. {summary["total_findings"]} finding(s) were identified
    across {summary["open_services"]} open service(s) on {len(scope["targets"])}
    target(s). The table below counts each finding by its severity; the sections
    that follow group the detail by the same bands, highest risk first.</p>
  <table class="count-table">
    <thead><tr><th>Vulnerability risk</th><th>Unique count</th></tr></thead>
    <tbody>
      {''.join(
        f'<tr><td style="color:{SEV_META[sev]["hex"]};font-weight:650">'
        f'{SEV_META[sev]["label"]} vulnerability</td>'
        f'<td class="num">{counts[sev]}</td></tr>'
        for sev in SEVERITY_ORDER)}
    </tbody>
  </table>

  <h2 id="scan-results">2. Scan results</h2>
  <div class="riskbar" role="img" aria-label="Findings by severity">{segments}</div>
  <div class="riskcounts">{chips}</div>
  <p class="total">{summary["total_findings"]} finding(s). Click a severity to filter.</p>

  <h2 id="methodology">3. Methodology</h2>
  <p class="prose">Targets {e(", ".join(scope["targets"]))} were probed on
    {scope["ports_scanned"]} TCP ports ({e(scope["port_range"])}) using
    {e(scope["method"])}. The scan runs in two phases: an availability phase that
    establishes which ports are reachable, and an assessment phase that probes each
    open port for its banner, TLS certificate and HTTP response, then applies the
    checks behind the findings in section 4. Checks cover exposed management and
    database services, anonymous access, TLS certificate and protocol weaknesses,
    HTTP security-header configuration, and version fingerprints matched against
    known CVEs. No exploitation, authentication attempts or denial-of-service
    testing were performed; results reflect the state visible from the scan source
    at {e(meta["started_at"])}</p>

  <h2 id="findings">4. Findings</h2>
  {severity_sections or '<p class="empty">No findings to report.</p>'}
  <h3 style="font-size:1.05rem;margin:2rem 0 .8rem">Detailed findings</h3>
  <div id="findings">{finding_blocks}</div>

  <h2 id="recommendations">5. Recommendations</h2>
  <p class="prose">Addressing the actions below in this order resolves the most
    findings with the least effort. The Vulns column counts affected findings and
    the Hosts column counts distinct services affected.</p>
  <table>
    <thead><tr><th>Remediation action</th><th>Severity</th><th>Vulns</th><th>Hosts</th></tr></thead>
    <tbody>{remed_html or '<tr><td colspan="4">Nothing to remediate.</td></tr>'}</tbody>
  </table>

  <h2 id="services">Appendix — observed services</h2>
  <table>
    <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Product</th>
      <th>TLS</th><th>Banner</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>

  <footer>Generated by {e(meta["scanner"]["name"])} {e(meta["scanner"]["version"])},
    report schema {e(report["report_version"])}</footer>
</div>
<script>
document.querySelectorAll('.riskcounts button').forEach(function (btn) {{
  btn.addEventListener('click', function () {{
    var sev = btn.dataset.sev;
    var active = btn.getAttribute('aria-pressed') === 'true';
    document.querySelectorAll('.riskcounts button').forEach(function (b) {{
      b.setAttribute('aria-pressed', 'false');
    }});
    btn.setAttribute('aria-pressed', active ? 'false' : 'true');
    document.querySelectorAll('.finding').forEach(function (f) {{
      f.hidden = !active && f.dataset.sev !== sev;
    }});
  }});
}});
</script>
</body>
</html>
"""


def _render_severity_section(sev: str, group: list) -> str:
    """One severity band heading followed by its finding cards.

    Mirrors the reference report's Risk Assessment bands, each opening with a
    one-line count and framing, highest risk first.
    """
    meta = SEV_META.get(sev, SEV_META["informational"])
    text = {
        "critical": "Critical vulnerabilities require immediate attention. They "
                    "are relatively easy for attackers to exploit and may provide "
                    "them with full control of the affected services.",
        "high": "High severity vulnerabilities are often harder to exploit and may "
                "not provide the same access to affected services.",
        "medium": "Medium severity vulnerabilities often provide information to "
                  "attackers that may assist them in mounting subsequent attacks. "
                  "Fix them in a timely manner.",
        "low": "Low severity vulnerabilities do not need to be patched immediately "
               "and can be resolved during the next maintenance window.",
        "informational": "Informational items are observations worth reviewing, not "
                         "immediate risks.",
    }.get(sev, "")
    cards = "".join(_render_finding(f) for f in group)
    return (f'<h3 style="font-size:1.1rem;margin:1.8rem 0 .5rem;color:{meta["hex"]}">'
            f'{meta["label"]} severity vulnerability</h3>'
            f'<p class="prose">{len(group)} finding(s). {text}</p>{cards}')


def _render_finding(f: dict) -> str:
    e = html.escape
    sev = SEV_META.get(f["severity"], SEV_META["informational"])
    tags = "".join(f'<span class="tag">{e(t)}</span>'
                   for t in (f["cwe"] + f["cve"] + [f["rule_id"]]))
    asset = f["asset"]
    location = asset.get("url") or (f"{asset.get('host')}:{asset.get('port')}/tcp")
    refs = "".join(
        f'<div><a href="{e(r)}" rel="noopener">{e(r)}</a></div>'
        for r in f.get("references", []))
    next_steps = "".join(
        f'<li><code>{e(s)}</code></li>'
        for s in f.get("next_steps", []))
    return f"""
<div class="finding" data-sev="{e(f["severity"])}"
     style="border-left-color:{sev["hex"]}">
  <div class="finding-head">
    <span class="fid">{e(f["id"])}</span>
    <span class="sev" style="background:{sev["wash"]};color:{sev["hex"]}">{sev["label"]}</span>
    <span class="sev" style="background:#f4f5f7;color:#4a515c">confidence: {e(f["confidence"])}</span>
    <h3>{e(f["title"])}</h3>
    <div class="tags">{tags}</div>
  </div>
  <dl>
    <dt>Affected asset</dt>
    <dd class="mono">{e(location)} · status {e(f["status"])}</dd>
    <dt>What was found</dt>
    <dd>{e(f["description"])}</dd>
    <dt>Impact</dt>
    <dd>{e(f["impact"])}</dd>
    <dt>Evidence</dt>
    <dd><pre>{e(f["evidence"])}</pre></dd>
    <dt>Recommendation</dt>
    <dd>{e(f["remediation"])}</dd>
    {f'<dt>Verify it yourself (authorized targets only)</dt><dd><ul>{next_steps}</ul></dd>' if next_steps else ''}
    {f'<dt>References</dt><dd>{refs}</dd>' if refs else ''}
  </dl>
</div>"""


def write_html(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_html(report))


# --------------------------------------------------------------------------
# Terminal summary
# --------------------------------------------------------------------------

def print_summary(report: dict, color: bool = True) -> None:
    summary = report["summary"]
    counts = summary["counts_by_severity"]
    def paint(text: str, sev: str) -> str:
        if not color:
            return text
        return f"{ANSI.get(sev, '')}{text}{ANSI_RESET}"

    print()
    print(f"  Scan of {', '.join(report['scope']['targets'])} — "
          f"{report['scope']['ports_scanned']} ports in "
          f"{report['metadata']['duration_seconds']}s")
    print(f"  {summary['open_services']} open service(s), "
          f"{summary['total_findings']} finding(s)\n")
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            label = SEV_META[sev]["label"]
            print(f"    {paint(f'{label:>14}', sev)}  {counts[sev]}")
    print()
    for finding in report["findings"]:
        if finding["severity"] == "informational":
            continue
        asset = finding["asset"]
        loc = asset.get("url") or f"{asset.get('host')}:{asset.get('port')}"
        sev_text = f"{finding['severity'].upper():<14}"
        sev_colored = paint(sev_text, finding["severity"]) if color else sev_text
        print(f"  [{finding['id']}] {sev_colored} {finding['title']} — {loc}")
    print()
