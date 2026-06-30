"""HTML report generator.

The generator renders a finding list as a self-contained HTML table with
severity-based color coding. All user-controlled fields are HTML-escaped
to prevent injection when findings contain resource names or descriptions
sourced from cloud APIs.
"""
from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from cms.core.models import ScanResult

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cloud Misconfig Scanner Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; color: #333; }}
        h1 {{ color: #222; }}
        .meta {{ color: #666; font-size: 0.9em; margin-bottom: 16px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; vertical-align: top; }}
        th {{ background-color: #f4f4f4; text-align: left; }}
        td.severity {{ font-weight: bold; text-align: center; white-space: nowrap; }}
        .CRITICAL {{ background-color: #f5b7b1; color: #641e16; }}
        .HIGH {{ background-color: #ffcccc; color: #7b241c; }}
        .MEDIUM {{ background-color: #fff0b3; color: #7d6608; }}
        .LOW {{ background-color: #e6f7ff; color: #1f618d; }}
        .empty {{ padding: 24px; text-align: center; color: #666; }}
    </style>
</head>
<body>
    <h1>Cloud Misconfig Scanner Report</h1>
    <div class="meta">Generated: {generated_at} &middot; Findings: {count}</div>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Rule ID</th>
                <th>Title</th>
                <th>Resource</th>
                <th>Description</th>
                <th>Remediation</th>
            </tr>
        </thead>
        <tbody>
{rows}
        </tbody>
    </table>
</body>
</html>
"""

_EMPTY_ROW = (
    '            <tr><td class="empty" colspan="6">'
    "No findings. Posture looks OK.</td></tr>\n"
)


def _esc(value) -> str:
    """HTML-escape an arbitrary value, converting it to str first."""
    return html.escape(str(value) if value is not None else "")


def _row_for(finding) -> str:
    severity = _esc(finding.severity)
    resource = _esc(f"{finding.resource.provider}:{finding.resource.name}")
    return (
        f"            <tr>"
        f'<td class="severity {severity}">{severity}</td>'
        f"<td>{_esc(finding.rule_id)}</td>"
        f"<td>{_esc(finding.title)}</td>"
        f"<td>{resource}</td>"
        f"<td>{_esc(finding.description)}</td>"
        f"<td>{_esc(finding.remediation)}</td>"
        f"</tr>\n"
    )


def generate_html_report(
    results: ScanResult,
    output_path: str | None = None,
) -> str:
    """Render ``results`` to an HTML file and return the path written.

    If ``output_path`` is None, a timestamped filename is generated in the
    current working directory.
    """
    rows = ""
    findings = getattr(results, "findings", []) or []
    if not findings:
        rows = _EMPTY_ROW
    else:
        for f in findings:
            rows += _row_for(f)

    html_content = HTML_TEMPLATE.format(
        generated_at=_esc(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        count=len(findings),
        rows=rows,
    )

    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"report_{timestamp}.html"

    Path(output_path).write_text(html_content, encoding="utf-8")
    print(f"[INFO] HTML report saved to {output_path}")
    return output_path
