# Cloud Misconfig Scanner

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![AWS](https://img.shields.io/badge/AWS-S3-orange.svg)](https://aws.amazon.com/s3/)
[![Last Commit](https://img.shields.io/github/last-commit/frangelbarrera/Cloud-Misconfig-Scanner)](https://github.com/frangelbarrera/Cloud-Misconfig-Scanner)

> A Python CLI tool for detecting misconfigurations in cloud storage services. Currently supports **AWS S3 with real API scanning**. Azure Blob and GCP Storage are on the roadmap.

## Features

### AWS S3 (Active)
- **Real API scanning** via boto3 (uses your AWS credentials)
- **Account-level Public Access Block** verification
- **Bucket-level Public Access Block** per bucket
- **Server-side encryption** detection
- **Versioning** status check
- **Bucket ACL** analysis (public-read, public-read-write)
- **Bucket Policy** analysis (public `Principal: *`)
- **Access logging** verification

### Azure Blob (Roadmap)
- Simulated mode only (real SDK integration planned)

### GCP Storage (Roadmap)
- Simulated mode only (real SDK integration planned)

## Quick Start

### Prerequisites
- Python 3.9+
- AWS account with read-only S3 permissions (for real scanning)
- AWS credentials configured (`~/.aws/credentials` or environment variables)

### Installation

```bash
git clone https://github.com/frangelbarrera/Cloud-Misconfig-Scanner.git
cd Cloud-Misconfig-Scanner
pip install -r requirements.txt
```

### Usage

#### Real AWS S3 Scan
```bash
# Using default AWS profile
python cms.py --provider aws

# Using specific profile
python cms.py --provider aws --profile my-profile

# JSON output
python cms.py --provider aws --format json

# HTML report (saved to report.html)
python cms.py --provider aws --format html
```

#### Simulated Mode (no AWS credentials needed)
```bash
python cms.py --provider aws --simulated
```

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

## Architecture

```
Cloud-Misconfig-Scanner/
├── cms.py                    # CLI entry point
├── cms/
│   ├── core/                 # Core engine
│   │   ├── models.py         # Resource, Finding, ScanResult dataclasses
│   │   ├── rules.py          # YAML rule loader
│   │   ├── reporter.py       # Text/JSON output
│   │   └── html_reporter.py  # HTML report generator
│   ├── providers/            # Cloud providers
│   │   ├── base.py           # ProviderScanner ABC
│   │   ├── aws_s3.py         # AWS S3 scanner (real API)
│   │   ├── azure_blob.py     # Azure Blob (simulated, roadmap)
│   │   └── gcp_storage.py    # GCP Storage (simulated, roadmap)
│   └── checks/               # YAML rule definitions
│       ├── aws_s3_rules.yaml
│       ├── azure_blob_rules.yaml
│       └── gcp_storage_rules.yaml
└── docs/
    └── iam/
        └── aws_least_privilege.json
```

## Output Formats

### Text (default)
```
[CRITICAL] S3-BUCKET-PUBLIC-ACL
  Resource: my-bucket
  Description: Bucket ACL allows public read access
  Remediation: Remove AllUsers grant from bucket ACL

[HIGH] S3-NO-ENCRYPTION
  Resource: another-bucket
  Description: Server-side encryption is not enabled
  Remediation: Enable SSE-S3 or SSE-KMS on the bucket
```

### JSON
```json
{
  "findings": [
    {
      "rule_id": "S3-BUCKET-PUBLIC-ACL",
      "severity": "CRITICAL",
      "resource": "my-bucket",
      "description": "Bucket ACL allows public read access",
      "remediation": "Remove AllUsers grant from bucket ACL"
    }
  ]
}
```

### HTML
Interactive HTML report with severity color-coding (CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue).

## Roadmap

- [x] AWS S3 real API scanning
- [ ] AWS S3 Bucket Policy deep analysis
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
- Test coverage (pytest + moto)
- CI/CD pipeline

## Security

- **Never commit** AWS credentials to the repo
- Use `~/.aws/credentials` or environment variables
- The scanner only requires **read-only** permissions
- See [`docs/iam/aws_least_privilege.json`](docs/iam/aws_least_privilege.json) for minimal policy

## License

MIT - see [LICENSE](LICENSE)
