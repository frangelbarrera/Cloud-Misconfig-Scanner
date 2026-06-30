"""Azure Blob Storage scanner (simulated mode in this phase).

Real SDK integration (``azure-storage-blob``) is on the roadmap. The
simulated mode emits one finding per rule in
``cms/checks/azure_blob_rules.yaml`` so that the CLI and reporters can be
exercised without Azure credentials.
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
    "azure_blob_rules.yaml",
)


class AzureBlobScanner(ProviderScanner):
    provider = "azure"
    service = "blob"

    def __init__(
        self,
        connection_string: str | None = None,
        rules_path: str | None = None,
    ):
        self.connection_string = connection_string
        self.simulated = not bool(connection_string)
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
                            name=f"container-{idx + 1}",
                            account="azure-account-id",
                            region="eastus",
                        ),
                        evidence={"simulated": True},
                    )
                )
            return res

        # Real Azure SDK integration is planned for a later phase.
        return res
