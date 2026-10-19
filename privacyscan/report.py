"""Table, JSON and HTML reports."""
import json
from html import escape

from .scanner import score

COL = {"high": "#e5484d", "medium": "#f5a623", "low": "#4c8bf5"}


def to_table(findings, files=0) -> str:
    lines = [f"PrivacyScan: {files} files, {len(findings)} findings, score {score(findings)}/100", ""]
    for f in findings:
        lines.append(f"[{f.severity.upper():<6}] {f.rule_id} {f.name}  ({f.article})")
        lines.append(f"         {f.path}:{f.line}   {f.snippet}")
        lines.append(f"         fix: {f.fix}")
    return "\n".join(lines)


def to_json(findings, files=0) -> str:
    return json.dumps({"files_scanned": files, "score": score(findings),
                       "findings": [f.to_dict() for f in findings]}, indent=2)


def to_html(findings, files=0, target="") -> str:
    s = score(findings)
    cnt = {k: sum(f.severity == k for f in findings) for k in COL}
    rows = "".join(
        f"<tr><td><b style='color:{COL[f.severity]}'>{f.severity.upper()}</b></td>"
        f"<td>{f.rule_id}<br>{escape(f.name)}</td>"
        f"<td>{escape(f.path)}:{f.line}<br><code>{escape(f.snippet)}</code></td>"
        f"<td>{escape(f.article)}</td><td>{escape(f.fix)}</td></tr>" for f in findings)
    ring = "#30a46c" if s >= 80 else "#f5a623" if s >= 50 else "#e5484d"
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>PrivacyScan report</title><style>
:root{{--bg:#f6f7f9;--p:#fff;--tx:#14171f;--m:#6a7282;--bd:#dfe3ea}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d0f14;--p:#161922;--tx:#e8eaf0;--m:#8a93a6;--bd:#262b38}}}}
body{{font-family:system-ui,sans-serif;background:var(--bg);color:var(--tx);max-width:1100px;margin:2rem auto;padding:0 1rem}}
.top{{display:flex;gap:16px;flex-wrap:wrap;align-items:center}}.score{{width:110px;height:110px;border-radius:50%;
border:10px solid {ring};display:flex;align-items:center;justify-content:center;font:700 30px system-ui}}
.card{{background:var(--p);border:1px solid var(--bd);border-radius:10px;padding:10px 16px}}.card b{{font-size:22px;display:block}}
table{{border-collapse:collapse;width:100%;margin-top:1.5rem;font-size:13px;background:var(--p)}}
td,th{{padding:8px;border-bottom:1px solid var(--bd);text-align:left;vertical-align:top}}code{{color:var(--m);word-break:break-all}}
.sub{{color:var(--m)}}</style></head><body>
<h1>🛡️ PrivacyScan report</h1><p class="sub">{escape(target)} · {files} files scanned · heuristic scan, not legal advice</p>
<div class="top"><div class="score">{s}</div>
<div class="card"><b style="color:{COL['high']}">{cnt['high']}</b>high</div>
<div class="card"><b style="color:{COL['medium']}">{cnt['medium']}</b>medium</div>
<div class="card"><b style="color:{COL['low']}">{cnt['low']}</b>low</div></div>
<table><tr><th>Severity</th><th>Rule</th><th>Location</th><th>GDPR</th><th>How to fix</th></tr>{rows}</table>
</body></html>"""
