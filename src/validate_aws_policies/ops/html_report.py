"""Self-contained HTML report for policy validation results.

The report is a single file: no external fonts, scripts or images, so it can be
opened offline and stored as a CI artifact. It has a light and a dark theme
(follows the OS setting, with a manual toggle), severity filters, search,
collapsible policies and a print stylesheet. Every value that comes from a policy
or from the API is HTML-escaped. Without JavaScript all content stays visible.
"""

import html
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..iam_access_analyzer.constants import SEVERITY_ORDER
from .findings import (
    count_by_type,
    finding_link,
    finding_message,
    finding_spans,
    is_placeholder,
)

SEVERITY_META = {
    "ERROR": ("Error", "sev-error", "\u2716"),
    "SECURITY_WARNING": ("Security warning", "sev-security", "\u26a0"),
    "WARNING": ("Warning", "sev-warning", "\u26a0"),
    "SUGGESTION": ("Suggestion", "sev-suggestion", "\u2139"),
}
UNKNOWN_META = ("Unknown", "sev-warning", "?")

CSS = """
:root{
  --bg:#f4f6f9;--surface:#fff;--surface-2:#f0f3f7;--text:#16191f;--muted:#5f6b7a;
  --border:#d9dfe7;--accent:#0972d3;--shadow:0 1px 2px rgba(15,25,40,.08),0 4px 14px rgba(15,25,40,.06);
  --err:#c62828;--err-bg:#fdeceb;--sec:#c2410c;--sec-bg:#fff0e6;
  --warn:#946200;--warn-bg:#fff6dc;--sug:#1b6e3c;--sug-bg:#e8f5ec;--ok:#1b6e3c;--ok-bg:#e8f5ec;
  --code-bg:#f6f8fa;
}
:root[data-theme=dark]{
  --bg:#0f1520;--surface:#18202d;--surface-2:#202a3a;--text:#e6ebf2;--muted:#93a1b5;
  --border:#2c3a4f;--accent:#58a6ff;--shadow:0 1px 2px rgba(0,0,0,.4),0 4px 14px rgba(0,0,0,.3);
  --err:#ff8a80;--err-bg:#3a1c1f;--sec:#ffab70;--sec-bg:#3a2617;
  --warn:#ffd166;--warn-bg:#3a3017;--sug:#7ee0a0;--sug-bg:#17301f;--ok:#7ee0a0;--ok-bg:#17301f;
  --code-bg:#111823;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme=light]){
    --bg:#0f1520;--surface:#18202d;--surface-2:#202a3a;--text:#e6ebf2;--muted:#93a1b5;
    --border:#2c3a4f;--accent:#58a6ff;--shadow:0 1px 2px rgba(0,0,0,.4),0 4px 14px rgba(0,0,0,.3);
    --err:#ff8a80;--err-bg:#3a1c1f;--sec:#ffab70;--sec-bg:#3a2617;
    --warn:#ffd166;--warn-bg:#3a3017;--sug:#7ee0a0;--sug-bg:#17301f;--ok:#7ee0a0;--ok-bg:#17301f;
    --code-bg:#111823;
  }
}
*{box-sizing:border-box}
html{color-scheme:light dark}
body{margin:0;background:var(--bg);color:var(--text);line-height:1.55;
  font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
a{color:var(--accent)}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
.wrap{max-width:1180px;margin:0 auto;padding:24px 20px 56px}
header.top{display:flex;gap:16px;align-items:flex-start;justify-content:space-between;
  flex-wrap:wrap;margin-bottom:20px}
h1{font-size:1.6rem;margin:0 0 4px;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:.9rem}
.btn{background:var(--surface);color:var(--text);border:1px solid var(--border);
  border-radius:8px;padding:6px 12px;font:inherit;font-size:.85rem;cursor:pointer}
.btn:hover{background:var(--surface-2)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.verdict{display:flex;align-items:center;gap:14px;border-radius:12px;padding:16px 20px;
  box-shadow:var(--shadow);border:1px solid var(--border);margin-bottom:18px;background:var(--surface)}
.verdict .icon{font-size:1.6rem;line-height:1}
.verdict h2{margin:0;font-size:1.1rem}
.verdict p{margin:2px 0 0;color:var(--muted);font-size:.9rem}
.verdict.fail{border-left:6px solid var(--err)}.verdict.fail .icon{color:var(--err)}
.verdict.warn{border-left:6px solid var(--warn)}.verdict.warn .icon{color:var(--warn)}
.verdict.pass{border-left:6px solid var(--ok)}.verdict.pass .icon{color:var(--ok)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px;
  box-shadow:var(--shadow);text-align:left;font:inherit;color:inherit}
button.card{cursor:pointer}
button.card:hover{border-color:var(--accent)}
button.card[aria-pressed=true]{outline:2px solid var(--accent)}
.card .n{display:block;font-size:1.8rem;font-weight:700;line-height:1.1}
.card .l{color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}
.card.sev-error .n{color:var(--err)}.card.sev-security .n{color:var(--sec)}
.card.sev-warning .n{color:var(--warn)}.card.sev-suggestion .n{color:var(--sug)}
.card.ok .n{color:var(--ok)}
.meta{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 18px;
  margin-bottom:18px;box-shadow:var(--shadow);display:grid;gap:6px;font-size:.88rem}
.meta b{color:var(--muted);font-weight:600;margin-right:6px}
.chip{display:inline-block;border:1px solid var(--border);background:var(--surface-2);
  border-radius:999px;padding:1px 10px;font-size:.78rem;margin:0 4px 2px 0}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.toolbar input[type=search]{flex:1 1 240px;min-width:200px;padding:8px 12px;border-radius:8px;
  border:1px solid var(--border);background:var(--surface);color:var(--text);font:inherit}
.toolbar label{font-size:.85rem;color:var(--muted);display:flex;gap:6px;align-items:center}
.policy{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  margin-bottom:10px;box-shadow:var(--shadow);overflow:hidden}
.policy>summary{list-style:none;cursor:pointer;display:flex;gap:10px;align-items:center;
  padding:12px 16px;flex-wrap:wrap}
.policy>summary::-webkit-details-marker{display:none}
.policy>summary::before{content:"\\25B8";color:var(--muted);transition:transform .15s}
.policy[open]>summary::before{transform:rotate(90deg)}
.policy .name{font-weight:600;word-break:break-all}
.policy .counts{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap}
.policy .body{padding:2px 16px 16px;border-top:1px solid var(--border)}
.badge{display:inline-flex;gap:5px;align-items:center;border-radius:6px;padding:1px 8px;
  font-size:.75rem;font-weight:700;letter-spacing:.02em;white-space:nowrap}
.badge.sev-error{background:var(--err-bg);color:var(--err)}
.badge.sev-security{background:var(--sec-bg);color:var(--sec)}
.badge.sev-warning{background:var(--warn-bg);color:var(--warn)}
.badge.sev-suggestion{background:var(--sug-bg);color:var(--sug)}
.badge.ok{background:var(--ok-bg);color:var(--ok)}
.finding{border:1px solid var(--border);border-left-width:5px;border-radius:8px;padding:10px 14px;
  margin-top:10px;background:var(--surface)}
.finding.sev-error{border-left-color:var(--err)}.finding.sev-security{border-left-color:var(--sec)}
.finding.sev-warning{border-left-color:var(--warn)}.finding.sev-suggestion{border-left-color:var(--sug)}
.finding .head{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.finding .code{font-size:.85rem}
.finding .msg{margin:6px 0 4px;white-space:pre-wrap;word-break:break-word}
.finding .facts{color:var(--muted);font-size:.82rem;display:flex;gap:14px;flex-wrap:wrap}
.reasons{margin:6px 0 0;padding-left:20px;font-size:.88rem}
details.raw{margin-top:8px}
details.raw summary{cursor:pointer;color:var(--muted);font-size:.82rem}
pre{background:var(--code-bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px;
  overflow:auto;font-size:.8rem;margin:6px 0 0}
.clean{color:var(--ok);margin-top:12px}
.checks{margin-top:12px;display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.checks .t{color:var(--muted);font-size:.82rem}
.empty{display:none;text-align:center;color:var(--muted);padding:30px}
footer{margin-top:28px;color:var(--muted);font-size:.82rem;text-align:center}
[hidden]{display:none!important}
@media print{
  body{background:#fff;color:#000}.toolbar,.btn,button.card:after{display:none!important}
  .policy>.body{display:block}.card,.policy,.verdict,.meta{box-shadow:none}
}
"""

JS = """
(function(){
  var root=document.documentElement,doc=document;
  root.className+=" js";
  var saved=null;try{saved=localStorage.getItem("vap-theme");}catch(e){}
  if(saved){root.setAttribute("data-theme",saved);}
  var tb=doc.getElementById("theme");
  if(tb){tb.onclick=function(){
    var dark=root.getAttribute("data-theme")==="dark"||
      (!root.getAttribute("data-theme")&&window.matchMedia&&
        window.matchMedia("(prefers-color-scheme: dark)").matches);
    var next=dark?"light":"dark";root.setAttribute("data-theme",next);
    try{localStorage.setItem("vap-theme",next);}catch(e){}
  };}
  var tools=doc.getElementById("tools");if(tools){tools.hidden=false;}
  var policies=[].slice.call(doc.querySelectorAll(".policy"));
  var active={};var search=doc.getElementById("q");var only=doc.getElementById("only");
  var cards=[].slice.call(doc.querySelectorAll("button.card[data-sev]"));
  function apply(){
    var q=(search.value||"").toLowerCase(),any=Object.keys(active).length>0,shown=0;
    policies.forEach(function(p){
      var finds=[].slice.call(p.querySelectorAll(".finding")),vis=0;
      finds.forEach(function(f){
        var ok=(!any||active[f.getAttribute("data-sev")])&&
          (!q||f.getAttribute("data-search").indexOf(q)>-1);
        f.hidden=!ok;if(ok){vis++;}
      });
      var nameMatch=q&&p.getAttribute("data-name").indexOf(q)>-1;
      var show=true;
      if(any||q){show=vis>0||(nameMatch&&!any);}
      if(only.checked&&finds.length===0){show=false;}
      p.hidden=!show;if(show){shown++;}
    });
    doc.getElementById("none").style.display=shown?"none":"block";
  }
  cards.forEach(function(c){c.onclick=function(){
    var s=c.getAttribute("data-sev");
    if(active[s]){delete active[s];c.setAttribute("aria-pressed","false");}
    else{active[s]=1;c.setAttribute("aria-pressed","true");}
    apply();
  };});
  search.oninput=apply;only.onchange=apply;
  doc.getElementById("expand").onclick=function(){policies.forEach(function(p){p.open=true;});};
  doc.getElementById("collapse").onclick=function(){policies.forEach(function(p){p.open=false;});};
  window.addEventListener("beforeprint",function(){policies.forEach(function(p){p.open=true;});});
})();
"""


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _safe_url(url: Optional[str]) -> Optional[str]:
    """Return the URL only if it is plain http(s); anything else is dropped."""
    if not url:
        return None
    parsed = urlparse(url)
    return url if parsed.scheme in ("http", "https") and parsed.netloc else None


def _severity(finding_type: str) -> Any:
    return SEVERITY_META.get(finding_type, UNKNOWN_META)


def _badge(finding_type: str) -> str:
    label, css, icon = _severity(finding_type)
    return f'<span class="badge {css}"><span aria-hidden="true">{icon}</span>{_esc(label)}</span>'


def _render_finding(finding: Dict[str, Any]) -> str:
    finding_type = str(finding.get("findingType", "UNKNOWN"))
    _label, css, _icon = _severity(finding_type)
    code = finding.get("issueCode") or "N/A"
    message = finding_message(finding)
    details = finding.get("details")
    is_check = isinstance(details, dict) and details.get("source") == "custom_check"

    facts = []
    spans = finding_spans(finding)
    if spans:
        start_line, start_col, _end_line, _end_col = spans[0]
        facts.append(f"Line {start_line}, column {start_col + 1}")
    if is_check:
        facts.append("Custom policy check")
    link = _safe_url(finding_link(finding))
    if link:
        facts.append(f'<a href="{_esc(link)}" target="_blank" rel="noopener noreferrer">Learn more</a>')

    reasons_html = ""
    check_reasons = details.get("reasons") if isinstance(details, dict) and is_check else None
    if check_reasons:
        items = []
        for reason in check_reasons:
            where = []
            if reason.get("statementId"):
                where.append(f"statement {_esc(reason['statementId'])}")
            if reason.get("statementIndex") is not None:
                where.append(f"index {_esc(reason['statementIndex'])}")
            suffix = f" <span class='sub'>({', '.join(where)})</span>" if where else ""
            items.append(f"<li>{_esc(reason.get('description', ''))}{suffix}</li>")
        reasons_html = f'<ul class="reasons">{"".join(items)}</ul>'

    raw_html = ""
    if isinstance(details, dict):
        raw = json.dumps(details, indent=2, default=str, ensure_ascii=False)
        raw_html = (
            '<details class="raw"><summary>Raw finding</summary>'
            f"<pre>{_esc(raw)}</pre></details>"
        )

    search = " ".join([finding_type, str(code), message]).lower()
    facts_html = f'<div class="facts">{" ".join(f"<span>{f}</span>" for f in facts)}</div>' if facts else ""
    return (
        f'<div class="finding {css}" data-sev="{_esc(finding_type)}" data-search="{_esc(search)}">'
        f'<div class="head">{_badge(finding_type)}<span class="code mono">{_esc(code)}</span></div>'
        f'<p class="msg">{_esc(message)}</p>{reasons_html}{facts_html}{raw_html}</div>'
    )


def _render_policy(result: Dict[str, Any]) -> str:
    name = str(result.get("filePolicy", "Unknown policy"))
    findings = [f for f in result.get("summary", []) if not is_placeholder(f)]
    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.index(f.get("findingType"))
            if f.get("findingType") in SEVERITY_ORDER
            else len(SEVERITY_ORDER)
        )
    )

    counts: Dict[str, int] = {}
    for finding in findings:
        kind = str(finding.get("findingType", "UNKNOWN"))
        counts[kind] = counts.get(kind, 0) + 1
    count_html = "".join(f'{_badge(kind)}<span class="sub">\u00d7{n}</span>' for kind, n in counts.items())
    if not findings:
        count_html = '<span class="badge ok"><span aria-hidden="true">\u2714</span>Clean</span>'

    body = "".join(_render_finding(f) for f in findings)
    if not findings:
        body = '<p class="clean">No findings. The policy passed validation.</p>'

    checks = result.get("checks") or []
    if checks:
        chips = []
        for check in checks:
            outcome = str(check.get("result", ""))
            css = {"PASS": "ok", "FAIL": "sev-error"}.get(outcome, "sev-warning")
            icon = {"PASS": "\u2714", "FAIL": "\u2716"}.get(outcome, "\u2013")
            chips.append(
                f'<span class="badge {css}"><span aria-hidden="true">{icon}</span>'
                f"{_esc(check.get('name', ''))}: {_esc(outcome)}</span>"
            )
        body += f'<div class="checks"><span class="t">Custom checks</span>{"".join(chips)}</div>'

    source = result.get("source") or {}
    source_html = ""
    if source:
        source_html = (
            f'<span class="chip mono" title="{_esc(source.get("file"))}">'
            f'{_esc(source.get("type"))} \u00b7 {_esc(source.get("resourceType"))}</span>'
        )
        body = (
            f'<p class="sub">Input: <span class="mono">{_esc(source.get("file"))}</span></p>'
            + body
        )

    opened = " open" if findings else ""
    return (
        f'<details class="policy"{opened} data-name="{_esc(name.lower())}">'
        f'<summary><span class="name mono">{_esc(name)}</span>{source_html}'
        f'<span class="counts">{count_html}</span></summary>'
        f'<div class="body">{body}</div></details>'
    )


def _verdict(counts: Dict[str, int], total: int) -> str:
    if counts["ERROR"]:
        return (
            '<div class="verdict fail" role="status"><span class="icon" aria-hidden="true">\u2716</span>'
            f"<div><h2>Validation failed</h2><p>{counts['ERROR']} error(s) must be fixed before "
            "these policies can be used.</p></div></div>"
        )
    if counts["SECURITY_WARNING"] or counts["WARNING"] or counts["SUGGESTION"]:
        return (
            '<div class="verdict warn" role="status"><span class="icon" aria-hidden="true">\u26a0</span>'
            "<div><h2>Passed with findings</h2><p>No errors, but review the warnings and "
            "suggestions below.</p></div></div>"
        )
    return (
        '<div class="verdict pass" role="status"><span class="icon" aria-hidden="true">\u2714</span>'
        f"<div><h2>All policies passed</h2><p>{total} policy file(s) validated with no "
        "findings.</p></div></div>"
    )


def render_html(
    results: List[Dict[str, Any]],
    generated_at: Optional[datetime] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """Render the full report document.

    Args:
        results: Validation results (``filePolicy``, ``summary`` and optional ``checks``)
        generated_at: Timestamp shown in the report (default: now)
        metadata: Optional run description: ``tool_version``, ``policy_sets``
            (list of ``{path, policy_type}``), ``locale`` and ``checks`` (names)

    Returns:
        HTML document as a string
    """
    generated_at = generated_at or datetime.now()
    metadata = metadata or {}
    counts = count_by_type(results)
    total = len(results)
    clean = sum(1 for r in results if not [f for f in r.get("summary", []) if not is_placeholder(f)])

    cards = [
        f'<div class="card"><span class="n">{total}</span><span class="l">Policies</span></div>',
        f'<div class="card ok"><span class="n">{clean}</span><span class="l">Clean</span></div>',
    ]
    for kind in SEVERITY_ORDER:
        label, css, _icon = SEVERITY_META[kind]
        cards.append(
            f'<button type="button" class="card {css}" data-sev="{kind}" aria-pressed="false" '
            f'title="Filter by {label.lower()}"><span class="n">{counts[kind]}</span>'
            f'<span class="l">{label}s</span></button>'
        )

    meta_rows = []
    sets = metadata.get("policy_sets") or []
    if sets:
        chips = "".join(
            f'<span class="chip mono">{_esc(s.get("path"))} \u00b7 {_esc(s.get("policy_type"))}</span>'
            for s in sets
        )
        meta_rows.append(f"<div><b>Policy sets</b>{chips}</div>")
    inputs = metadata.get("inputs") or []
    if inputs:
        chips = "".join(
            f'<span class="chip mono">{_esc(i.get("file"))} \u00b7 {_esc(i.get("type"))} '
            f'\u00b7 {_esc(i.get("policies"))} policies</span>'
            for i in inputs
        )
        meta_rows.append(f"<div><b>Inputs</b>{chips}</div>")
    skipped = metadata.get("skipped") or []
    if skipped:
        items = "".join(
            f'<li><span class="mono">{_esc(i.get("id"))}</span> '
            f'<span class="sub">{_esc(i.get("reason"))}</span></li>'
            for i in skipped
        )
        meta_rows.append(
            f"<div><b>Not validated</b>{len(skipped)} policies could not be checked because "
            f'their value is not known before deployment.<ul class="reasons">{items}</ul></div>'
        )
    if metadata.get("checks"):
        chips = "".join(f'<span class="chip">{_esc(c)}</span>' for c in metadata["checks"])
        meta_rows.append(f"<div><b>Custom checks</b>{chips}</div>")
    if metadata.get("locale"):
        meta_rows.append(f"<div><b>Locale</b>{_esc(metadata['locale'])}</div>")
    meta_html = f'<section class="meta" aria-label="Run details">{"".join(meta_rows)}</section>' if meta_rows else ""

    version = _esc(metadata.get("tool_version", ""))
    version_txt = f" v{version}" if version else ""
    policies_html = "".join(_render_policy(r) for r in results)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="validate-aws-policies{version_txt}">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>AWS Policy Validation Report</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <div>
    <h1>AWS Policy Validation Report</h1>
    <div class="sub">IAM Access Analyzer \u00b7 generated {_esc(generated_at.strftime("%Y-%m-%d %H:%M:%S"))}</div>
  </div>
  <button type="button" class="btn" id="theme" aria-label="Toggle light and dark theme">Theme</button>
</header>
{_verdict(counts, total)}
<section class="cards" aria-label="Summary">{"".join(cards)}</section>
{meta_html}
<div class="toolbar" id="tools" hidden>
  <input type="search" id="q" placeholder="Search policy, issue code or message" aria-label="Search findings">
  <label><input type="checkbox" id="only"> Only policies with findings</label>
  <button type="button" class="btn" id="expand">Expand all</button>
  <button type="button" class="btn" id="collapse">Collapse all</button>
</div>
<main id="policies">{policies_html}
<div class="empty" id="none">No policies match the current filters.</div>
</main>
<footer>validate-aws-policies{version_txt} \u00b7 IAM Access Analyzer</footer>
</div>
<script>{JS}</script>
</body>
</html>
"""
