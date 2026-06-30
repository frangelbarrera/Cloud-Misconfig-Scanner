"""Tests for the text/JSON reporters and severity filtering."""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

from cms.core.models import Finding, Resource, ScanResult
from cms.core.reporter import filter_by_severity, print_json, print_text


def _resource(name="b"):
    return Resource(
        provider="aws", service="s3", account="1", region="us-east-1", name=name
    )


def _finding(severity, rule_id="R"):
    return Finding(
        rule_id=rule_id,
        title="title",
        severity=severity,
        description="desc",
        remediation="fix",
        resource=_resource(),
        evidence={},
    )


def test_print_text_no_findings():
    buf = io.StringIO()
    with redirect_stdout(buf):
        print_text(ScanResult())
    assert "No findings" in buf.getvalue()


def test_print_text_lists_findings():
    buf = io.StringIO()
    with redirect_stdout(buf):
        print_text(ScanResult(findings=[_finding("HIGH", "AWS-S3-ENCRYPTION")]))
    out = buf.getvalue()
    assert "[HIGH]" in out
    assert "AWS-S3-ENCRYPTION" in out


def test_print_json_outputs_valid_json():
    buf = io.StringIO()
    with redirect_stdout(buf):
        print_json(ScanResult(findings=[_finding("LOW")]))
    payload = json.loads(buf.getvalue())
    assert isinstance(payload, list)
    assert payload[0]["severity"] == "LOW"
    assert payload[0]["resource"]["provider"] == "aws"


def test_filter_by_severity_threshold():
    findings = [
        _finding("LOW", "L"),
        _finding("MEDIUM", "M"),
        _finding("HIGH", "H"),
        _finding("CRITICAL", "C"),
    ]
    res = ScanResult(findings=findings)
    high_only = filter_by_severity(res, "HIGH")
    assert {f.rule_id for f in high_only} == {"H", "C"}


def test_filter_by_severity_none_returns_all():
    findings = [_finding("LOW"), _finding("CRITICAL")]
    out = filter_by_severity(ScanResult(findings=findings), None)
    assert len(out) == 2
