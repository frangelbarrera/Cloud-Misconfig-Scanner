from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Resource:
    provider: str           # "aws" | "azure" | "gcp"
    service: str            # "s3" | "blob" | "storage"
    account: str            # account/subscription/project
    region: Optional[str]
    name: str               # bucket/container name
    meta: dict = field(default_factory=dict)

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str           # "LOW"|"MEDIUM"|"HIGH"|"CRITICAL"
    description: str
    remediation: str
    resource: Resource
    evidence: dict = field(default_factory=dict)

@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)

    def add(self, f: Finding):
        self.findings.append(f)
