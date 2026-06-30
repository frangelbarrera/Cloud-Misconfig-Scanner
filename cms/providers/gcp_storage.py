"""GCP Cloud Storage scanner (simulated mode in this phase).

Real SDK integration (``google-cloud-storage``) is on the roadmap. The
simulated mode emits one finding per rule in
``cms/checks/gcp_storage_rules.yaml`` so that the CLI and reporters can be
exercised without GCP credentials.
"""
from __future__ import annotations

import os
from collections.abc import Iterable

from cms.core.models import Finding, ScanResult
from cms.core.rules import RuleRegistry, load_registry
from cms.providers.base import ProviderScanner

DEFAULT_RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "checks",
    "gcp_storage_rules.yaml",
)


class GcpStorageScanner(ProviderScanner):
    provider = "gcp"
    service = "storage"

    def __init__(
        self,
        credentials_path: str | None = None,
        rules_path: str | None = None,
    ):
        self.credentials_path = credentials_path
        self.simulated = not bool(credentials_path)
        self.rules: RuleRegistry = load_registry(
            rules_path or DEFAULT_RULES_PATH
        )

    def scan(self, targets: Iterable[str] | None = None) -> ScanResult:
        res = ScanResult()

        if self.simulated:
            for idx, rule in enumerate(self.rules):
                res.add(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        description=rule.description,
                        remediation=rule.remediation,
                        resource=self._resource(
                            name=f"bucket-{idx + 1}",
                            account="gcp-project-id",
                            region="us-central1",
                        ),
                        evidence={"simulated": True},
                    )
                )
            return res

        # Real GCP SDK integration is planned for a later phase.
        return res
