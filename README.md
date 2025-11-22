# Cloud-Misconfig-Scanner

**Cloud-Misconfig-Scanner** is a multi-cloud security auditing tool designed to detect common storage misconfigurations across **AWS S3**, **Azure Blob Storage**, and **Google Cloud Storage**.

It is built with a modular architecture, supports multiple output formats (**Text**, **JSON**, **HTML**), and includes a **simulated mode** that works without cloud credentials — making it ideal for demonstrations, portfolio projects, and offline testing.

> **Status:** This project is an **MVP** (Minimum Viable Product).  
> AWS, Azure, and GCP modules currently support **simulated scanning**.  
> Real cloud API integration is planned for future releases.

---

## ✨ Features

- **Multi-cloud support**: AWS, Azure, and GCP scanning modules.
- **Simulated mode**: Run full scans without cloud credentials.
- **Multiple output formats**:
  - **Text** (CLI-friendly)
  - **JSON** (machine-readable)
  - **HTML** (color-coded, shareable reports)
- **Rule-based scanning**: Misconfigurations defined in YAML for easy updates.
- **Extensible architecture**: Add new providers or rules with minimal changes.

---

## 📂 Project Structure

```
Cloud-Misconfig-Scanner/
│
├── cms/                        # Core application package
│   ├── checks/                  # Misconfiguration rule definitions (YAML)
│   │   ├── aws_s3_rules.yaml
│   │   ├── azure_blob_rules.yaml
│   │   └── gcp_storage_rules.yaml
│   │
│   ├── core/                    # Core logic and utilities
│   │   ├── html_reporter.py     # HTML report generator
│   │   ├── models.py            # Data models (Resource, Finding, ScanResult)
│   │   ├── reporter.py          # Text/JSON output functions
│   │   ├── rules.py              # YAML rule loader
│   │   └── utils.py              # Helper functions
│   │
│   ├── providers/               # Cloud provider-specific scanners
│   │   ├── aws_s3.py             # AWS S3 scanner (simulated/real)
│   │   ├── azure_blob.py         # Azure Blob scanner (simulated/real)
│   │   ├── gcp_storage.py        # GCP Storage scanner (simulated/real)
│   │   └── base.py               # Base scanner class/interface
│   │
│   └── export/                   # Export templates and generated reports
│       ├── templates/
│       └── report.html
│
├── docs/                        # Documentation and IAM policy references
│   └── iam/
│       ├── azure_least_privilege.json
│       ├── gcp_least_privilege.md
│       └── gcp_least_privilege.pdf
│
├── requirements.txt             # Python dependencies
├── cms.py                       # CLI entry point
└── README.md                    # Project documentation
```

---

## 🚀 Usage

### Simulated Mode (no credentials required)
```bash
# AWS simulated scan
python cms.py --provider aws --format text

# Azure simulated scan
python cms.py --provider azure --format json

# GCP simulated scan
python cms.py --provider gcp --format html

# Multi-cloud simulated scan
python cms.py --provider all --format html
```

### Output Examples
- **Text**: CLI-friendly list of findings.
- **JSON**: Machine-readable output for integration.
- **HTML**: Color-coded report with severity highlighting.

---

## 🛠 Roadmap

- [ ] Implement real AWS S3 API integration.
- [ ] Implement real Azure Blob Storage API integration.
- [ ] Implement real GCP Storage API integration.
- [ ] Expand rule sets for each provider.
- [ ] Add unit and integration tests.
- [ ] CI/CD pipeline for automated testing and releases.

---

## 🤝 Contributing
Contributions are welcome!  
Fork the repository, create a feature branch, and submit a pull request.

---

**Cloud-Misconfig-Scanner** — Inspect, detect, and secure your cloud storage configurations.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
