

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from .models import OverallResult

# Band -> accent colour (background, text).
_BAND_COLORS = {
    "low": ("#1b7f3b", "#e7f6ec"),
    "medium": ("#b7791f", "#fdf6e3"),
    "high": ("#c2410c", "#fff1e8"),
    "critical": ("#b91c1c", "#fdecec"),
}
_SEVERITY_COLORS = {
    "info": "#64748b",
    "low": "#2563eb",
    "medium": "#b7791f",
    "high": "#c2410c",
}
_MODULE_LABELS = {
    "header": "Header & authentication",
    "link": "Links & destinations",
    "language": "Language & wording",
}


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _bar(score: int, color: str) -> str:
    pct = max(0, min(100, score))
    return (
        '<div class="bar"><div class="bar-fill" '
        f'style="width:{pct}%;background:{color}"></div>'
        f'<span class="bar-label">{score}/100</span></div>'
    )


def _meta_rows(result: OverallResult) -> str:
    email = result.email
    rows = [
        ("From", email.from_addr or "(none)"),
        ("Subject", email.subject or "(none)"),
        ("Reply-To", email.reply_to or "(none)"),
        ("Return-Path", email.return_path or "(none)"),
        ("Date", email.date or "(none)"),
        ("Links found", len(email.links)),
        ("Source", email.source or "(in-memory message)"),
    ]
    return "\n".join(
        f"<tr><th>{_esc(label)}</th><td>{_esc(value)}</td></tr>"
        for label, value in rows
    )


def _module_section(result: OverallResult) -> str:
    blocks = []
    for module in result.modules:
        label = _MODULE_LABELS.get(module.name, module.name.title())
        band = result.band  # module bars use a neutral accent
        color = _SEVERITY_COLORS["high"] if module.score >= 50 else (
            _SEVERITY_COLORS["medium"] if module.score >= 25 else _SEVERITY_COLORS["low"]
        )
        weight = result.weights.get(module.name)
        weight_txt = f" &middot; weight {weight:.0%}" if weight is not None else ""
        rows = _findings_rows(module.findings)
        blocks.append(
            f'<section class="module">'
            f'<h3>{_esc(label)} <span class="muted">({_esc(module.name)}{weight_txt})</span></h3>'
            f'{_bar(module.score, color)}'
            f'<table class="findings">{rows}</table>'
            f'</section>'
        )
    return "\n".join(blocks)


def _findings_rows(findings) -> str:
    scored = [f for f in findings if f.points > 0]
    info = [f for f in findings if f.points == 0]
    rows = []
    for f in scored + info:
        color = _SEVERITY_COLORS.get(f.severity, "#64748b")
        pts = f"+{f.points}" if f.points else "0"
        rows.append(
            "<tr>"
            f'<td class="sev"><span class="pill" style="background:{color}">'
            f'{_esc(f.severity)}</span></td>'
            f'<td class="pts">{pts}</td>'
            f"<td><strong>{_esc(f.title)}</strong><br>"
            f'<span class="muted">{_esc(f.detail)}</span></td>'
            "</tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="3" class="muted">No findings.</td></tr>')
    header = (
        '<tr class="head"><th>Severity</th><th>Pts</th><th>Finding</th></tr>'
    )
    return header + "".join(rows)


def render_html(result: OverallResult) -> str:
    """Return the full HTML document for an :class:`OverallResult`."""
    bg, fg = _BAND_COLORS.get(result.band, ("#334155", "#e2e8f0"))
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = _esc(result.email.subject or result.email.source or "Email")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing risk report &mdash; {title}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         margin: 0; background: #f1f5f9; color: #0f172a; }}
  .wrap {{ max-width: 880px; margin: 0 auto; padding: 24px; }}
  .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
          padding: 20px 24px; margin-bottom: 18px; box-shadow: 0 1px 2px rgba(0,0,0,.04); }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  h3 {{ font-size: 15px; margin: 18px 0 8px; }}
  .muted {{ color: #64748b; font-weight: normal; }}
  .verdict {{ display: flex; align-items: center; gap: 18px; }}
  .badge {{ background: {bg}; color: {fg}; border-radius: 10px; padding: 14px 20px;
           text-align: center; min-width: 150px; }}
  .badge .band {{ font-size: 22px; font-weight: 700; text-transform: uppercase;
                 letter-spacing: .5px; }}
  .badge .score {{ font-size: 13px; opacity: .9; }}
  .bar {{ position: relative; background: #e2e8f0; border-radius: 6px; height: 22px;
         margin: 6px 0 4px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 6px 0 0 6px; }}
  .bar-label {{ position: absolute; right: 8px; top: 1px; font-size: 12px;
               color: #0f172a; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .meta th {{ text-align: left; width: 130px; color: #475569; font-weight: 600;
             padding: 4px 8px; vertical-align: top; white-space: nowrap; }}
  .meta td {{ padding: 4px 8px; vertical-align: top; word-break: break-word; }}
  .findings td, .findings th {{ padding: 7px 8px; border-top: 1px solid #eef2f7;
                               text-align: left; vertical-align: top; }}
  .findings tr.head th {{ border-top: none; color: #475569; font-size: 12px; }}
  .findings .pts {{ font-variant-numeric: tabular-nums; white-space: nowrap;
                   color: #334155; }}
  .findings .sev {{ white-space: nowrap; }}
  .pill {{ color: #fff; border-radius: 999px; padding: 2px 9px; font-size: 11px;
          text-transform: uppercase; letter-spacing: .4px; }}
  footer {{ text-align: center; color: #94a3b8; font-size: 12px; padding: 8px 0 24px; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>Phishing Risk Report</h1>
    <div class="muted" style="margin-bottom:14px">{title}</div>
    <div class="verdict">
      <div class="badge">
        <div class="band">{_esc(result.band)}</div>
        <div class="score">risk score {result.score}/100</div>
      </div>
      <div style="flex:1">{_bar(result.score, bg)}</div>
    </div>
  </div>

  <div class="card">
    <h3>Message</h3>
    <table class="meta">{_meta_rows(result)}</table>
  </div>

  <div class="card">
    <h3>Per-module breakdown</h3>
    {_module_section(result)}
  </div>

  <footer>Generated by phish_analyzer (rule-based) &middot; {generated}</footer>
</div>
</body>
</html>
"""


def write_html(result: OverallResult, path: str | Path) -> Path:
    """Render *result* and write it to *path*; returns the path written."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Malformed source emails can decode to lone surrogate code points, which are
    # not encodable to UTF-8. Encode with "replace" so report writing never fails.
    path.write_bytes(render_html(result).encode("utf-8", "replace"))
    return path
