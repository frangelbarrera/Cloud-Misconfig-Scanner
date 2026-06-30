"""Text and JSON reporters.

Both reporters accept an optional ``min_severity`` filter so the CLI can
downgrade noise (e.g., only show HIGH and CRITICAL findings).
"""
from __future__ import annotations

import json

from cms.core.models import ScanResult

# Higher number == more severe. Anything below the threshold is hidden.
SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _severity_value(severity: str) -> int:
    return SEVERITY_ORDER.get((severity or "").upper(), 0)


def filter_by_severity(
    results: ScanResult, min_severity: str | None
) -> list:
    """Return only findings at or above ``min_severity``."""
    findings = getattr(results, "findings", []) or []
    if not min_severity:
        return list(findings)
    threshold = _severity_value(min_severity)
    return [f for f in findings if _severity_value(f.severity) >= threshold]


def print_text(
    results: ScanResult, min_severity: str | None = None
) -> None:
    findings = filter_by_severity(results, min_severity)
    if not findings:
        print("No findings. Posture looks OK.")
        return
    print("Findings:")
    for f in findings:
        print(
            f"- [{f.severity}] {f.rule_id} | {f.title} "
            f"-> {f.resource.provider}:{f.resource.name}"
        )


def print_json(
    results: ScanResult, min_severity: str | None = None
) -> None:
    findings = filter_by_severity(results, min_severity)
    payload = []
    for f in findings:
        item = {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "description": f.description,
            "remediation": f.remediation,
            "resource": {
                "provider": f.resource.provider,
                "service": f.resource.service,
                "account": f.resource.account,
                "region": f.resource.region,
                "name": f.resource.name,
                "meta": f.resource.meta,
            },
            "evidence": f.evidence,
        }
        payload.append(item)
    print(json.dumps(payload, indent=2, default=str))
