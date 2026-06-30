"""Tests for the YAML rule loader and registry."""
from __future__ import annotations

import textwrap

import pytest

from cms.core.rules import Rule, RuleRegistry, load_registry, load_rules


def _write_yaml(tmp_path, content: str):
    path = tmp_path / "rules.yaml"
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return str(path)


def test_load_rules_returns_empty_for_missing_file(tmp_path):
    assert load_rules(str(tmp_path / "nope.yaml")) == []


def test_load_rules_parses_basic_fields(tmp_path):
    path = _write_yaml(
        tmp_path,
        """
        - id: AWS-S3-ENCRYPTION
          title: No default server-side encryption
          severity: HIGH
          description: Bucket has no default SSE.
          remediation: Enable SSE-S3 or SSE-KMS.
        """,
    )
    rules = load_rules(path)
    assert len(rules) == 1
    rule = rules[0]
    assert rule.id == "AWS-S3-ENCRYPTION"
    assert rule.severity == "HIGH"
    assert "SSE" in rule.remediation


def test_load_rules_normalises_missing_severity(tmp_path):
    path = _write_yaml(
        tmp_path,
        """
        - id: SOME-RULE
          title: Some rule
          description: d
          remediation: r
        """,
    )
    rules = load_rules(path)
    assert rules[0].severity == "MEDIUM"


def test_registry_lookup_by_id(tmp_path):
    path = _write_yaml(
        tmp_path,
        """
        - id: R1
          title: t1
          severity: LOW
          description: d
          remediation: r
        - id: R2
          title: t2
          severity: HIGH
          description: d
          remediation: r
        """,
    )
    registry = load_registry(path)
    assert len(registry) == 2
    assert registry.get("R1").severity == "LOW"
    assert registry.get("MISSING") is None


def test_registry_require_raises_key_error_with_available_list(tmp_path):
    registry = RuleRegistry([Rule("R1", "t", "LOW", "d", "r")])
    with pytest.raises(KeyError) as exc:
        registry.require("NOPE")
    assert "R1" in str(exc.value)


def test_default_aws_s3_rules_load_successfully():
    """The bundled AWS S3 rules file must parse and contain known IDs."""
    import os

    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "cms",
        "checks",
        "aws_s3_rules.yaml",
    )
    registry = load_registry(path)
    expected_ids = {
        "AWS-S3-ACCOUNT-BPA",
        "AWS-S3-BUCKET-BPA",
        "AWS-S3-ENCRYPTION",
        "AWS-S3-VERSIONING",
        "AWS-S3-PUBLIC-ACL",
        "AWS-S3-PUBLIC-POLICY",
        "AWS-S3-NO-LOGGING",
        "AWS-S3-NO-MFA-DELETE",
    }
    assert expected_ids.issubset({r.id for r in registry})
