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
pip install -r requirements-dev.txt
pip install -e .

# Run tests with coverage (>=80% enforced)
pytest -v

# Lint
ruff check cms tests

# Verify the CLI works
python cms.py --provider aws --simulated  # simulated mode
```

## Code Style
- **Python**: PEP 8, type hints encouraged (modern `X | None` syntax with `from __future__ import annotations`)
- **Imports**: stdlib → third-party → local (enforced by `ruff`/isort)
- **Docstrings**: Google style for public functions
- **Tests**: Required for new checks (use `moto` for AWS mocking)
- **Lint**: `ruff check cms tests` must pass before merge
- **Coverage**: `pytest --cov=cms --cov-fail-under=80` is enforced by CI

## Adding a New AWS S3 Check

1. Add the rule entry to `cms/checks/aws_s3_rules.yaml` (id, title, severity, description, remediation)
2. Add the check logic to `cms/providers/aws_s3.py` (call `self._add_finding(res, "RULE-ID", resource, evidence=...)`)
3. Add a test in `tests/test_aws_s3_scanner.py` using `moto` to mock the bucket state
4. Update README if user-facing
5. Run `pytest` and `ruff check cms tests` before committing

## Adding a New Cloud Provider

1. Create `cms/providers/<provider>_<service>.py`
2. Subclass `ProviderScanner` from `cms/providers/base.py` and set `provider` and `service` class attributes
3. Implement the `scan()` method with real API calls
4. Load rules via `RuleRegistry(load_registry(path))` so finding metadata comes from YAML
5. Add YAML rules in `cms/checks/<provider>_<service>_rules.yaml`
6. Register the provider in `cms/cli.py` (`_scan_all` function)
7. Add IAM permissions docs in `docs/iam/`
8. Add tests using `moto` (AWS) or the equivalent mock framework

## Security Considerations

- **Never commit** AWS/Azure/GCP credentials
- **Never commit** `.pyc`, `__pycache__/`, or generated reports
- Use `.env` for local secrets (already in `.gitignore`)
- Test only against sandbox/cloud accounts you own

## Areas Needing Help

- [ ] Azure Blob real API implementation (`azure-storage-blob`)
- [ ] GCP Storage real API implementation (`google-cloud-storage`)
- [ ] AWS IAM scanning module
- [ ] SARIF output format
- [ ] Docker container support
- [ ] Slack webhook notifications

## License

By contributing, you agree your contributions will be licensed under the MIT License.
