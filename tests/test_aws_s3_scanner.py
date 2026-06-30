"""Tests for the AWS S3 scanner using moto to mock the AWS API."""
from __future__ import annotations

import boto3

try:
    from moto import mock_aws  # type: ignore
except ImportError:  # pragma: no cover
    from moto import mock_s3 as mock_aws  # type: ignore

from cms.providers.aws_s3 import AwsS3Scanner


def _make_bucket(name, **kwargs):
    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket=name)
    if kwargs.get("bpa"):
        client.put_public_access_block(
            Bucket=name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
    if kwargs.get("encryption"):
        client.put_bucket_encryption(
            Bucket=name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            },
        )
    if kwargs.get("versioning"):
        client.put_bucket_versioning(
            Bucket=name, VersioningConfiguration={"Status": "Enabled"}
        )
    if kwargs.get("logging"):
        client.create_bucket(Bucket=f"{name}-logs")
        client.put_bucket_logging(
            Bucket=name,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": f"{name}-logs",
                    "TargetPrefix": f"{name}/",
                }
            },
        )
    return client


def _scan():
    """Run a real-mode scan against the moto mock environment."""
    with mock_aws():
        scanner = AwsS3Scanner(simulated=False)
        return scanner.scan()


# --------------------------------------------------------------------------- #
# Simulated mode
# --------------------------------------------------------------------------- #


def test_simulated_mode_emits_one_finding_per_rule(aws_credentials):
    scanner = AwsS3Scanner(simulated=True)
    result = scanner.scan()
    rule_ids = {f.rule_id for f in result.findings}
    assert "AWS-S3-ACCOUNT-BPA" in rule_ids
    assert "AWS-S3-PUBLIC-ACL" in rule_ids
    assert "AWS-S3-NO-MFA-DELETE" in rule_ids
    assert all(f.evidence.get("simulated") for f in result.findings)


def test_simulated_findings_are_in_english(aws_credentials):
    """Phase 1 bug fix: simulated findings must not contain Spanish text."""
    scanner = AwsS3Scanner(simulated=True)
    result = scanner.scan()
    spanish_markers = ("Descripción", "prueba", "requiere acción", "flujo")
    for f in result.findings:
        for marker in spanish_markers:
            assert marker not in f.description, (
                f"Spanish marker '{marker}' found in description: {f.description}"
            )
            assert marker not in f.remediation


# --------------------------------------------------------------------------- #
# Auto-detection
# --------------------------------------------------------------------------- #


def test_auto_detect_simulated_when_no_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setattr(
        "cms.providers.aws_s3.DEFAULT_AWS_CREDENTIALS_PATH",
        "/tmp/definitely-missing-aws-creds",
    )
    scanner = AwsS3Scanner()
    assert scanner.simulated is True


def test_auto_detect_real_when_env_creds_present(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    scanner = AwsS3Scanner()
    assert scanner.simulated is False


# --------------------------------------------------------------------------- #
# Real-mode bucket checks
# --------------------------------------------------------------------------- #


def test_real_mode_detects_unencrypted_unversioned_bucket(aws_credentials):
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="bucket-one")
        scanner = AwsS3Scanner(simulated=False)
        result = scanner.scan()

    ids = {f.rule_id for f in result.findings}
    assert "AWS-S3-ENCRYPTION" in ids
    assert "AWS-S3-VERSIONING" in ids
    assert "AWS-S3-ACCOUNT-BPA" in ids  # no account BPA set in moto
    assert "AWS-S3-BUCKET-BPA" in ids


def test_real_mode_skips_encrypted_versioned_bucket(aws_credentials):
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="healthy")
        client.put_bucket_encryption(
            Bucket="healthy",
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            },
        )
        client.put_bucket_versioning(
            Bucket="healthy",
            VersioningConfiguration={"Status": "Enabled"},
        )
        # Enable BPA on the bucket to clear that finding.
        client.put_public_access_block(
            Bucket="healthy",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        scanner = AwsS3Scanner(simulated=False)
        result = scanner.scan(["healthy"])

    ids = {f.rule_id for f in result.findings if f.resource.name == "healthy"}
    assert "AWS-S3-ENCRYPTION" not in ids
    assert "AWS-S3-VERSIONING" not in ids
    assert "AWS-S3-BUCKET-BPA" not in ids


def test_real_mode_detects_missing_logging(aws_credentials):
    """Bucket without server access logging must trigger AWS-S3-NO-LOGGING."""
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="no-logs-bucket")
        scanner = AwsS3Scanner(simulated=False)
        result = scanner.scan(["no-logs-bucket"])

    ids = {f.rule_id for f in result.findings if f.resource.name == "no-logs-bucket"}
    assert "AWS-S3-NO-LOGGING" in ids


def test_real_mode_logging_enabled_suppresses_finding(aws_credentials):
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="logged-bucket")
        client.create_bucket(Bucket="logged-bucket-logs")
        # Grant the S3 log-delivery group WRITE + READ_ACP on the target
        # bucket so that put_bucket_logging succeeds in moto.
        client.put_bucket_acl(
            Bucket="logged-bucket-logs",
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "Type": "Group",
                            "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                        },
                        "Permission": "WRITE",
                    },
                    {
                        "Grantee": {
                            "Type": "Group",
                            "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                        },
                        "Permission": "READ_ACP",
                    },
                ],
                "Owner": {"DisplayName": "owner", "ID": "abc"},
            },
        )
        client.put_bucket_logging(
            Bucket="logged-bucket",
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": "logged-bucket-logs",
                    "TargetPrefix": "logged-bucket/",
                }
            },
        )
        scanner = AwsS3Scanner(simulated=False)
        result = scanner.scan(["logged-bucket"])

    ids = {f.rule_id for f in result.findings if f.resource.name == "logged-bucket"}
    assert "AWS-S3-NO-LOGGING" not in ids


def test_real_mode_detects_public_acl(aws_credentials):
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="public-acl")
        client.put_bucket_acl(
            Bucket="public-acl",
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "Type": "Group",
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                        },
                        "Permission": "READ",
                    }
                ],
                "Owner": {"DisplayName": "owner", "ID": "abc"},
            },
        )
        scanner = AwsS3Scanner(simulated=False)
        result = scanner.scan(["public-acl"])

    ids = {f.rule_id for f in result.findings}
    assert "AWS-S3-PUBLIC-ACL" in ids
    public_acl_finding = next(f for f in result.findings if f.rule_id == "AWS-S3-PUBLIC-ACL")
    assert public_acl_finding.severity == "CRITICAL"


def test_real_mode_detects_public_policy(aws_credentials):
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="public-policy")
        client.put_bucket_policy(
            Bucket="public-policy",
            Policy="""{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::public-policy/*"
                }]
            }""",
        )
        scanner = AwsS3Scanner(simulated=False)
        result = scanner.scan(["public-policy"])

    ids = {f.rule_id for f in result.findings}
    assert "AWS-S3-PUBLIC-POLICY" in ids


def test_real_mode_account_bpa_empty_dict_still_fires(aws_credentials):
    """Phase 1 bug fix: empty account_bpa must trigger the finding."""
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="bucket-test")
        scanner = AwsS3Scanner(simulated=False)
        result = scanner.scan()

    account_bpa_findings = [
        f for f in result.findings if f.rule_id == "AWS-S3-ACCOUNT-BPA"
    ]
    assert len(account_bpa_findings) >= 1, (
        "Empty account BPA config must trigger AWS-S3-ACCOUNT-BPA finding"
    )


def test_targets_filter_narrows_scan(aws_credentials):
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="targeted-bucket")
        client.create_bucket(Bucket="not-targeted-bucket")
        scanner = AwsS3Scanner(simulated=False)
        result = scanner.scan(["targeted-bucket"])

    scanned_names = {f.resource.name for f in result.findings}
    assert "not-targeted-bucket" not in scanned_names


def test_lazy_init_does_not_call_sts_in_constructor(aws_credentials):
    """Phase 1 bug fix: STS must NOT be called in __init__."""
    # Without mock_aws active, calling STS would fail. Constructing the
    # scanner should not raise.
    scanner = AwsS3Scanner(simulated=False)
    assert scanner._session is None  # noqa: SLF001
    assert scanner._account is None  # noqa: SLF001


def test_real_mode_falls_back_to_simulated_on_invalid_creds(monkeypatch):
    """If STS fails at scan time, scanner must fall back to simulated."""
    # Force real mode by env vars but do NOT activate mock_aws, so STS will
    # fail at scan time.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "invalid")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "invalid")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setattr(
        "cms.providers.aws_s3.DEFAULT_AWS_CREDENTIALS_PATH",
        "/tmp/definitely-missing-aws-creds",
    )
    scanner = AwsS3Scanner(simulated=False)
    result = scanner.scan()
    # We expect the fallback warning + simulated findings.
    rule_ids = {f.rule_id for f in result.findings}
    assert "AWS-S3-SCAN-WARNING" in rule_ids
    assert "AWS-S3-ACCOUNT-BPA" in rule_ids  # from simulated rules
