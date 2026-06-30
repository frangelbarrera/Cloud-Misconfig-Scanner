"""AWS S3 misconfiguration scanner.

The scanner supports two execution modes:

* **Real mode** (default). Uses boto3 with the caller's AWS credentials to
  inspect every bucket in the account (or only those passed via ``targets``)
  for the following misconfigurations:

  - Account-level Block Public Access (BPA) not fully enabled
  - Bucket-level BPA with disabled flags
  - Missing default server-side encryption
  - Versioning disabled or suspended
  - Bucket ACL granting access to AllUsers / AllAuthenticatedUsers
  - Bucket policy with a ``Principal: "*"`` Allow statement
  - Server access logging disabled
  - MFA Delete not enabled

* **Simulated mode**. Activated when no AWS credentials are detected (no
  ``~/.aws/credentials`` file, no ``AWS_ACCESS_KEY_ID`` env var, no
  ``AWS_PROFILE``) or when explicitly requested with ``simulated=True``.
  The scanner then emits one finding per rule in
  ``cms/checks/aws_s3_rules.yaml`` against a fake bucket, so that CI
  pipelines and downstream tooling can exercise the reporter and CLI
  without cloud credentials.

The previous implementation made an STS ``get_caller_identity`` call in
``__init__``, which crashed at construction time whenever credentials were
invalid. We now do lazy client initialization inside :meth:`scan` and
gracefully fall back to simulated mode if STS fails.
"""
from __future__ import annotations

import os
from collections.abc import Iterable

import boto3
import botocore

from cms.core.models import Finding, ScanResult
from cms.core.rules import RuleRegistry, load_registry
from cms.providers.base import ProviderScanner

# Path to the default AWS credentials file. Resolved at import time so that
# tests can monkeypatch it if needed.
DEFAULT_AWS_CREDENTIALS_PATH = os.path.expanduser("~/.aws/credentials")

# All four account-level and bucket-level BPA flags that must be enabled.
BPA_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)

# URI prefixes used by S3 ACLs to identify public groups.
PUBLIC_ACL_GRANTEES = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AllAuthenticatedUsers",
)

DEFAULT_RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "checks",
    "aws_s3_rules.yaml",
)


class AwsS3Scanner(ProviderScanner):
    """Scanner implementation for AWS S3."""

    provider = "aws"
    service = "s3"

    def __init__(
        self,
        profile: str | None = None,
        region: str | None = None,
        simulated: bool | None = None,
        rules_path: str | None = None,
    ):
        self.profile = profile
        self.region = region or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
        self.rules: RuleRegistry = load_registry(rules_path or DEFAULT_RULES_PATH)

        # Mode resolution: explicit override wins, otherwise auto-detect.
        if simulated is None:
            self.simulated = self._auto_detect_simulated()
        else:
            self.simulated = bool(simulated)

        # Lazy-initialized boto3 clients. Populated by _ensure_clients().
        self._session: boto3.Session | None = None
        self._s3 = None
        self._s3control = None
        self._account: str | None = None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def scan(self, targets: Iterable[str] | None = None) -> ScanResult:
        res = ScanResult()

        if self.simulated:
            return self._scan_simulated(res)

        try:
            self._ensure_clients()
        except Exception as exc:
            # Fall back to simulated mode if real credentials are not usable.
            # We still log the failure as a finding so users can diagnose.
            res.add(
                Finding(
                    rule_id="AWS-S3-SCAN-WARNING",
                    title="AWS credentials not usable, falling back to simulated mode",
                    severity="LOW",
                    description=f"STS get_caller_identity failed: {exc}",
                    remediation=(
                        "Configure valid AWS credentials (~/.aws/credentials "
                        "or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY env vars) "
                        "and ensure the iam:GetCallerIdentity permission is granted."
                    ),
                    resource=self._resource("account"),
                    evidence={"simulated_fallback": True},
                )
            )
            self.simulated = True
            return self._scan_simulated(res)

        buckets = self._resolve_buckets(targets)
        account_bpa = self._get_account_bpa()

        for name in buckets:
            self._scan_bucket(name, account_bpa, res)

        return res

    # ------------------------------------------------------------------ #
    # Simulated mode
    # ------------------------------------------------------------------ #

    def _scan_simulated(self, res: ScanResult) -> ScanResult:
        """Emit one finding per rule in the YAML against a fake bucket."""
        fake_resource = self._resource(
            name="simulated-bucket",
            account="000000000000",
            region=self.region,
        )
        for rule in self.rules:
            res.add(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    description=rule.description,
                    remediation=rule.remediation,
                    resource=fake_resource,
                    evidence={"simulated": True},
                )
            )
        return res

    # ------------------------------------------------------------------ #
    # Real-mode helpers
    # ------------------------------------------------------------------ #

    def _auto_detect_simulated(self) -> bool:
        """Return True when no AWS credentials are detectable."""
        if os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get(
            "AWS_SECRET_ACCESS_KEY"
        ):
            return False
        if os.environ.get("AWS_PROFILE"):
            return False
        if self.profile:
            return False
        return not os.path.exists(DEFAULT_AWS_CREDENTIALS_PATH)

    def _ensure_clients(self) -> None:
        """Build boto3 clients and resolve the account id lazily."""
        if self._session is not None:
            return
        session_kwargs = {}
        if self.profile:
            session_kwargs["profile_name"] = self.profile
        self._session = boto3.Session(**session_kwargs)
        self._s3 = self._session.client("s3", region_name=self.region)
        self._s3control = self._session.client("s3control", region_name="us-east-1")
        self._account = self._session.client("sts").get_caller_identity()["Account"]

    def _resolve_buckets(self, targets: Iterable[str] | None) -> list[str]:
        if targets:
            return [t.strip() for t in targets if t and t.strip()]
        resp = self._s3.list_buckets()
        return [b["Name"] for b in resp.get("Buckets", [])]

    def _get_account_bpa(self) -> dict:
        try:
            return self._s3control.get_public_access_block(
                AccountId=self._account
            )["PublicAccessBlockConfiguration"]
        except botocore.exceptions.ClientError:
            return {}

    def _scan_bucket(self, name: str, account_bpa: dict, res: ScanResult) -> None:
        resource = self._resource(
            name=name, account=self._account or "000000000000", region=self.region
        )

        # --- Account-level BPA ---
        # Bug fix from Phase 1: when account_bpa is {} (no config set at all)
        # the previous code computed `all({}) == True` and skipped the finding.
        # We now treat missing config as "not fully enabled".
        if not account_bpa or not all(account_bpa.get(k, False) for k in BPA_FLAGS):
            self._add_finding(
                res,
                "AWS-S3-ACCOUNT-BPA",
                resource,
                evidence={"account_bpa": account_bpa},
            )

        # --- Bucket-level BPA ---
        bpa = self._get_bucket_bpa(name)
        if bpa is None or not all(bpa.get(k, False) for k in BPA_FLAGS):
            self._add_finding(
                res,
                "AWS-S3-BUCKET-BPA",
                resource,
                evidence={"bucket_bpa": bpa or {}},
            )

        # --- Encryption ---
        sse = self._get_bucket_encryption(name)
        if not sse:
            self._add_finding(
                res,
                "AWS-S3-ENCRYPTION",
                resource,
                evidence={"sse": sse or "none"},
            )

        # --- Versioning + MFA Delete ---
        versioning = self._get_bucket_versioning(name)
        if versioning.get("Status") != "Enabled":
            self._add_finding(
                res,
                "AWS-S3-VERSIONING",
                resource,
                evidence={"versioning": versioning.get("Status", "disabled")},
            )
        # MFA Delete only applies when versioning is enabled.
        if versioning.get("Status") == "Enabled" and not versioning.get("MFADelete"):
            self._add_finding(
                res,
                "AWS-S3-NO-MFA-DELETE",
                resource,
                evidence={"mfa_delete": versioning.get("MFADelete", "Disabled")},
            )

        # --- Bucket ACL ---
        public_acl_grants = self._get_public_acl_grants(name)
        if public_acl_grants:
            self._add_finding(
                res,
                "AWS-S3-PUBLIC-ACL",
                resource,
                evidence={"public_grants": public_acl_grants},
            )

        # --- Bucket Policy ---
        if self._bucket_policy_is_public(name):
            self._add_finding(
                res,
                "AWS-S3-PUBLIC-POLICY",
                resource,
                evidence={"policy_public": True},
            )

        # --- Access Logging ---
        if not self._is_logging_enabled(name):
            self._add_finding(
                res,
                "AWS-S3-NO-LOGGING",
                resource,
                evidence={"logging_enabled": False},
            )

    # ------------------------------------------------------------------ #
    # Per-bucket API helpers
    # ------------------------------------------------------------------ #

    def _get_bucket_bpa(self, name: str) -> dict | None:
        try:
            return self._s3.get_public_access_block(Bucket=name)[
                "PublicAccessBlockConfiguration"
            ]
        except botocore.exceptions.ClientError:
            return None

    def _get_bucket_encryption(self, name: str) -> str | None:
        try:
            rules = self._s3.get_bucket_encryption(Bucket=name)[
                "ServerSideEncryptionConfiguration"
            ]["Rules"]
            if not rules:
                return None
            return rules[0]["ApplyServerSideEncryptionByDefault"].get("SSEAlgorithm")
        except botocore.exceptions.ClientError:
            return None
        except (KeyError, IndexError):
            return None

    def _get_bucket_versioning(self, name: str) -> dict:
        try:
            return self._s3.get_bucket_versioning(Bucket=name)
        except botocore.exceptions.ClientError:
            return {}

    def _get_public_acl_grants(self, name: str) -> list[dict]:
        try:
            acl = self._s3.get_bucket_acl(Bucket=name)
        except botocore.exceptions.ClientError:
            return []
        public = []
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if uri in PUBLIC_ACL_GRANTEES:
                public.append(
                    {"grantee": uri, "permission": grant.get("Permission")}
                )
        return public

    def _bucket_policy_is_public(self, name: str) -> bool:
        import json

        try:
            policy_text = self._s3.get_bucket_policy(Bucket=name)["Policy"]
        except botocore.exceptions.ClientError:
            return False
        if not policy_text:
            return False
        try:
            policy = (
                json.loads(policy_text)
                if isinstance(policy_text, str)
                else policy_text
            )
        except (ValueError, TypeError):
            return False
        for stmt in policy.get("Statement", []) or []:
            if not isinstance(stmt, dict):
                continue
            if str(stmt.get("Effect", "")).lower() != "allow":
                continue
            principal = stmt.get("Principal")
            if principal == "*" or (
                isinstance(principal, dict) and principal.get("AWS") == "*"
            ):
                return True
        return False

    def _is_logging_enabled(self, name: str) -> bool:
        try:
            logging = self._s3.get_bucket_logging(Bucket=name)
        except botocore.exceptions.ClientError:
            return False
        return bool(logging.get("LoggingEnabled"))

    # ------------------------------------------------------------------ #
    # Finding helpers
    # ------------------------------------------------------------------ #

    def _add_finding(
        self,
        res: ScanResult,
        rule_id: str,
        resource,
        evidence: dict,
    ) -> None:
        rule = self.rules.get(rule_id)
        if rule is None:
            # Fall back to a synthetic rule if YAML is missing the entry.
            res.add(
                Finding(
                    rule_id=rule_id,
                    title=rule_id,
                    severity="MEDIUM",
                    description=f"Rule {rule_id} triggered but is not defined in YAML.",
                    remediation="Add the rule to cms/checks/aws_s3_rules.yaml.",
                    resource=resource,
                    evidence=evidence,
                )
            )
            return
        res.add(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                description=rule.description,
                remediation=rule.remediation,
                resource=resource,
                evidence=evidence,
            )
        )
