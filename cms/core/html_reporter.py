from pathlib import Path
from datetime import datetime
from cms.core.models import ScanResult

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Cloud Misconfig Scanner Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; }}
        th {{ background-color: #f4f4f4; }}
        .HIGH {{ background-color: #ffcccc; }}
        .MEDIUM {{ background-color: #fff0b3; }}
        .LOW {{ background-color: #e6f7ff; }}
    </style>
</head>
<body>
    <h1>Cloud Misconfig Scanner Report</h1>
    <table>
        <tr>
            <th>Severity</th>
            <th>Rule ID</th>
            <th>Title</th>
            <th>Resource</th>
            <th>Description</th>
            <th>Remediation</th>
        </tr>
        {rows}
    </table>
</body>
</html>
"""

def generate_html_report(results: ScanResult, output_path: str = None):
    rows = ""
    for f in results.findings:
        rows += f"<tr class='{f.severity}'>"
        rows += f"<td>{f.severity}</td>"
        rows += f"<td>{f.rule_id}</td>"
        rows += f"<td>{f.title}</td>"
        rows += f"<td>{f.resource.provider}:{f.resource.name}</td>"
        rows += f"<td>{f.description}</td>"
        rows += f"<td>{f.remediation}</td>"
        rows += "</tr>\n"

    html_content = HTML_TEMPLATE.format(rows=rows)

    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"report_{timestamp}.html"

    Path(output_path).write_text(html_content, encoding="utf-8")
    print(f"[INFO] HTML report saved to {output_path}")
