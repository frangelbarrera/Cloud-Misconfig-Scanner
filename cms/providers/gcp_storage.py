import os
from cms.core.models import Resource, Finding, ScanResult
from cms.core.rules import load_rules

class GcpStorageScanner:
    def __init__(self, credentials_path=None):
        self.credentials_path = credentials_path
        self.simulated = not bool(credentials_path)
        self.rules = load_rules("cms/checks/gcp_storage_rules.yaml")

    def _resource(self, name, meta=None):
        return Resource(
            provider="gcp",
            service="storage",
            account="gcp-project-id",
            region="us-central1",
            name=name,
            meta=meta or {}
        )

    def scan(self, targets=None) -> ScanResult:
        res = ScanResult()

        if self.simulated:
            for idx, rule in enumerate(self.rules):
                res.add(Finding(
                    rule.id,
                    rule.title,
                    rule.severity,
                    rule.description,
                    rule.remediation,
                    self._resource(f"bucket-{idx+1}"),
                    {"simulated": True}
                ))
            return res

        # FUTURE GCP SDK
        return res
