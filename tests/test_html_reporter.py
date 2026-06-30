"""Tests for the HTML reporter."""
from __future__ import annotations

import html as html_module
from pathlib import Path

from cms.core.html_reporter import generate_html_report
from cms.core.models import Finding, Resource, ScanResult


def _resource(name="b"):
    return Resource(
        provider="aws", service="s3", account="123", region="us-east-1", name=name
    )


def test_html_report_escapes_xss_payload(tmp_path):
    payload = "<script>alert('xss')</script>"
    finding = Finding(
        rule_id=payload,
        title=payload,
        severity="HIGH",
        description=payload,
        remediation=payload,
        resource=_resource(payload),
        evidence={},
    )
    out = generate_html_report(
        ScanResult(findings=[finding]),
        output_path=str(tmp_path / "out.html"),
    )
    content = Path(out).read_text(encoding="utf-8")
    assert "<script>alert('xss')</script>" not in content
    assert html_module.escape(payload) in content


def test_html_report_renders_critical_severity(tmp_path):
    finding = Finding(
        rule_id="AWS-S3-PUBLIC-ACL",
        title="Bucket ACL allows public access",
        severity="CRITICAL",
        description="desc",
        remediation="fix",
        resource=_resource(),
        evidence={},
    )
    out = generate_html_report(
        ScanResult(findings=[finding]),
        output_path=str(tmp_path / "out.html"),
    )
    content = Path(out).read_text(encoding="utf-8")
    assert "CRITICAL" in content
    assert 'class="severity CRITICAL"' in content


def test_html_report_renders_empty_findings_message(tmp_path):
    out = generate_html_report(
        ScanResult(findings=[]), output_path=str(tmp_path / "out.html")
    )
    content = Path(out).read_text(encoding="utf-8")
    assert "No findings" in content
    assert "Findings: 0" in content


def test_html_report_auto_generates_filename_when_no_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = generate_html_report(ScanResult(findings=[]))
    assert out.startswith("report_")
    assert out.endswith(".html")
    assert Path(out).exists()
