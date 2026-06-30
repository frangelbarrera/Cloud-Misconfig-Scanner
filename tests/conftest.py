"""Pytest fixtures shared across the test suite."""
from __future__ import annotations

import boto3
import pytest

# moto v5+ exposes mock_aws as the single decorator; older versions used
# mock_s3. We support either.
try:
    from moto import mock_aws  # type: ignore
except ImportError:  # pragma: no cover - moto<5 fallback
    from moto import mock_s3 as mock_aws  # type: ignore


@pytest.fixture
def aws_credentials(monkeypatch):
    """Stub AWS credentials so boto3 doesn't try to use the host's creds."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    # Force the AwsS3Scanner auto-detect to think real creds exist.
    monkeypatch.setattr(
        "cms.providers.aws_s3.DEFAULT_AWS_CREDENTIALS_PATH",
        "/tmp/nonexistent-aws-credentials",
    )


@pytest.fixture
def s3_client(aws_credentials):
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        sts = boto3.client("sts", region_name="us-east-1")
        account = sts.get_caller_identity()["Account"]
        yield client, account


@pytest.fixture
def scanner(aws_credentials):
    """Build an AwsS3Scanner pointed at the mock AWS env."""
    from cms.providers.aws_s3 import AwsS3Scanner

    with mock_aws():
        scanner = AwsS3Scanner(simulated=False)
        yield scanner
