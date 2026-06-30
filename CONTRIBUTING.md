# Contributing to Cloud Misconfig Scanner

Thanks for your interest in improving cloud security! This tool aims to be a lightweight, storage-focused cloud security scanner.

## How to Contribute

### Reporting Bugs
- Open an issue with the **bug** label
- Include: OS, Python version, AWS profile config (sanitized), full error traceback
- Paste the command you ran and the output

### Suggesting Features
- Open an issue with the **enhancement** label
- Describe the use case and expected behavior
- Reference similar features in Prowler, ScoutSuite, or CloudSploit if applicable

### Submitting Pull Requests
1. Fork the repository
2. Create a branch: `git checkout -b feature/your-feature`
3. Make your changes following PEP 8
4. Test with real AWS credentials in a sandbox account (NEVER production)
5. Commit with clear messages
6. Open a Pull Request against `main`

## Development Setup

```bash
git clone https://github.com/frangelbarrera/Cloud-Misconfig-Scanner.git
cd Cloud-Misconfig-Scanner
pip install -r requirements.txt
python cms.py --provider aws --simulated  # verify it runs
```

## Code Style
- **Python**: PEP 8, type hints encouraged
- **Imports**: stdlib → third-party → local (isort)
- **Docstrings**: Google style for public functions
- **Tests**: Required for new checks (use `moto` for AWS mocking)

## Adding a New AWS S3 Check

1. Add the check logic to `cms/providers/aws_s3.py`
2. Add a rule entry to `cms/checks/aws_s3_rules.yaml`
3. Test with `moto` mock or real AWS sandbox
4. Update README if user-facing

## Adding a New Cloud Provider

1. Create `cms/providers/<provider>_<service>.py`
2. Subclass `ProviderScanner` from `cms/providers/base.py`
3. Implement `scan()` method with real API calls
4. Add YAML rules in `cms/checks/<provider>_<service>_rules.yaml`
5. Update `cms.py` CLI to support the new provider
6. Add IAM permissions docs in `docs/iam/`

## Security Considerations

- **Never commit** AWS/Azure/GCP credentials
- **Never commit** `.pyc`, `__pycache__/`, or generated reports
- Use `.env` for local secrets (already in `.gitignore`)
- Test only against sandbox/cloud accounts you own

## Areas Needing Help

- [ ] Azure Blob real API implementation (`azure-storage-blob`)
- [ ] GCP Storage real API implementation (`google-cloud-storage`)
- [ ] Test coverage with `pytest` + `moto`
- [ ] GitHub Actions CI pipeline
- [ ] SARIF output format
- [ ] Docker container support

## License

By contributing, you agree your contributions will be licensed under the MIT License.
