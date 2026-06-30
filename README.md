# Cloud Misconfig Scanner

[![CI](https://github.com/frangelbarrera/Cloud-Misconfig-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/frangelbarrera/Cloud-Misconfig-Scanner/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![AWS](https://img.shields.io/badge/AWS-S3-orange.svg)](https://aws.amazon.com/s3/)
[![Last Commit](https://img.shields.io/github/last-commit/frangelbarrera/Cloud-Misconfig-Scanner)](https://github.com/frangelbarrera/Cloud-Misconfig-Scanner)

> A Python CLI tool for detecting misconfigurations in cloud storage services. **AWS S3 is fully supported with real API scanning.** Azure Blob and GCP Storage currently run in simulated mode (roadmap).

## Features

### AWS S3 (Active)
- **Real API scanning** via boto3 (auto-detects your AWS credentials)
- **Account-level Block Public Access (BPA)** verification
- **Bucket-level BPA** per bucket (all four flags checked)
- **Server-side encryption** detection
- **Versioning** status check
- **Bucket ACL** analysis — flags `AllUsers` / `AllAuthenticatedUsers` grants as CRITICAL
- **Bucket Policy** analysis — flags `Principal: "*"` Allow statements as CRITICAL
- **Server access logging** verification
- **MFA Delete** status check (when versioning is enabled)
- **Simulated mode** as a graceful fallback when no AWS credentials are present
- **YAML-driven rules** — all finding metadata lives in `cms/checks/aws_s3_rules.yaml`, consistent with Azure/GCP

### Azure Blob (Roadmap)
- Simulated mode only (real SDK integration planned)

### GCP Storage (Roadmap)
- Simulated mode only (real SDK integration planned)

## Quick Start

### Prerequisites
- Python 3.9+
- AWS account with read-only S3 permissions (for real scanning)
- AWS credentials configured (`~/.aws/credentials` or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars)

### Installation

```bash
git clone https://github.com/frangelbarrera/Cloud-Misconfig-Scanner.git
cd Cloud-Misconfig-Scanner

# Runtime dependencies
pip install -r requirements.txt

# OR: editable install (also registers the console script)
pip install -e .
```

### Usage

#### Real AWS S3 Scan (default behaviour)
```bash
# Auto-detects credentials and runs in real mode
python cms.py --provider aws

# Using a specific profile
python cms.py --provider aws --profile my-profile

# JSON output
python cms.py --provider aws --format json

# HTML report to a specific file
python cms.py --provider aws --format html -o report.html

# Only show HIGH and CRITICAL findings
python cms.py --provider aws --severity HIGH

# Scan only specific buckets
python cms.py --provider aws --targets bucket-a,bucket-b
```

#### Simulated Mode

Simulated mode emits one finding per rule in `cms/checks/aws_s3_rules.yaml` against a fake bucket, so you can exercise the CLI/reporters without cloud credentials.

```bash
# Force simulated mode (useful for CI / sandbox testing)
python cms.py --provider aws --simulated
```

If no AWS credentials are detected at all, the scanner auto-falls-back to simulated mode.

### Exit Codes

| Code | Meaning                            |
|------|------------------------------------|
| 0    | No findings (posture looks clean)  |
| 1    | Findings detected                  |
| 2    | CLI usage error                    |
| 3    | Scanner runtime error              |

### Required AWS IAM Permissions

The scanner requires read-only S3 permissions. See [`docs/iam/aws_least_privilege.json`](docs/iam/aws_least_privilege.json) for the minimal policy.

Key permissions:
- `s3:ListAllMyBuckets`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetBucketEncryption`
- `s3:GetBucketVersioning`
- `s3:GetBucketAcl`
- `s3:GetBucketPolicy`
- `s3:GetBucketLogging`
- `s3control:GetPublicAccessBlock`
- `sts:GetCallerIdentity`

## Architecture

```
Cloud-Misconfig-Scanner/
├── cms.py                    # Legacy CLI entry point (delegates to cms.cli)
├── cms/
│   ├── __init__.py
│   ├── __main__.py           # Allows `python -m cms`
│   ├── cli.py                # CLI implementation (argparse + exit codes)
│   ├── core/                 # Core engine
│   │   ├── models.py         # Resource, Finding, ScanResult dataclasses
│   │   ├── rules.py          # YAML rule loader + RuleRegistry
│   │   ├── reporter.py       # Text/JSON output + severity filtering
│   │   └── html_reporter.py  # HTML report (XSS-safe, CRITICAL supported)
│   ├── providers/            # Cloud providers (all subclass ProviderScanner)
│   │   ├── base.py           # ProviderScanner ABC + shared helpers
│   │   ├── aws_s3.py         # AWS S3 scanner (real API + simulated fallback)
│   │   ├── azure_blob.py     # Azure Blob (simulated, roadmap)
│   │   └── gcp_storage.py    # GCP Storage (simulated, roadmap)
│   └── checks/               # YAML rule definitions
│       ├── aws_s3_rules.yaml
│       ├── azure_blob_rules.yaml
│       └── gcp_storage_rules.yaml
├── tests/                    # pytest + moto test suite
│   ├── conftest.py
│   ├── test_rules.py
│   ├── test_reporter.py
│   ├── test_html_reporter.py
│   ├── test_aws_s3_scanner.py
│   └── test_cli.py
├── docs/
│   └── iam/
│       ├── aws_least_privilege.json
│       ├── azure_least_privilege.md
│       └── gcp_least_privilege.md
├── .github/workflows/ci.yml  # GitHub Actions: pytest + ruff on push/PR
├── pyproject.toml            # pip install -e . support + tool config
├── requirements.txt          # Runtime deps
└── requirements-dev.txt      # Test/lint deps
```

## Output Formats

### Text (default)
```
Findings:
- [CRITICAL] AWS-S3-PUBLIC-ACL | Bucket ACL allows public access -> aws:my-bucket
- [HIGH] AWS-S3-ENCRYPTION | No default server-side encryption -> aws:another-bucket
```

### JSON
```json
[
  {
    "rule_id": "AWS-S3-PUBLIC-ACL",
    "title": "Bucket ACL allows public access",
    "severity": "CRITICAL",
    "description": "...",
    "remediation": "...",
    "resource": {
      "provider": "aws", "service": "s3", "account": "123456789012",
      "region": "us-east-1", "name": "my-bucket", "meta": {}
    },
    "evidence": { "public_grants": [{"grantee": "http://acs.amazonaws.com/groups/global/AllUsers", "permission": "READ"}] }
  }
]
```

### HTML
Self-contained HTML report with severity color-coding (CRITICAL=red, HIGH=pink, MEDIUM=yellow, LOW=blue). All fields are HTML-escaped to prevent XSS.

## Development

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .

# Run tests with coverage (>=80% enforced)
pytest -v

# Lint
ruff check cms tests
```

## Roadmap

- [x] AWS S3 real API scanning
- [x] AWS S3 Bucket Policy deep analysis (Principal: "*" detection)
- [x] AWS S3 Bucket ACL analysis (AllUsers / AllAuthenticatedUsers)
- [x] AWS S3 Access Logging verification
- [x] AWS S3 MFA Delete verification
- [x] YAML-driven AWS rules (consistency with Azure/GCP)
- [x] Tests with moto + pytest (>=80% core coverage)
- [x] GitHub Actions CI (pytest + ruff)
- [x] CLI improvements: --output, --severity, exit codes
- [x] HTML reporter: XSS fix, CRITICAL severity
- [ ] AWS IAM scanning (overly permissive policies)
- [ ] Azure Blob real API scanning
- [ ] GCP Storage real API scanning
- [ ] CIS Benchmark ID mapping
- [ ] CSV output format
- [ ] SARIF output for GitHub code scanning
- [ ] Slack webhook notifications
- [ ] Docker container support

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

Areas needing help:
- Azure Blob real API implementation
- GCP Storage real API implementation
- AWS IAM scanning module
- SARIF output format

## Security

- **Never commit** AWS credentials to the repo
- Use `~/.aws/credentials` or environment variables
- The scanner only requires **read-only** permissions
- See [`docs/iam/aws_least_privilege.json`](docs/iam/aws_least_privilege.json) for minimal policy

## License

MIT - see [LICENSE](LICENSE)
