**Maintainer:** Frangel Raúl Crespo Barrera
**Last verified:** 2026-10-02
**Scope:** AWS scanner operations, IAM permissions, account/region/profile selection, and report handling.

| Field | Current record |
|---|---|
| Status | AWS implementation and tests exist; Azure/GCP are roadmap items unless code proves otherwise. |
| Evidence | `cms/`, `tests/test_aws_s3_scanner.py`, `tests/test_rules.py`, `pyproject.toml`, `.github/workflows/ci.yml`. |
| Verification | `pytest -q`; use mocks and no real credentials in tests; review permissions per operation. |
| Owner | Repository owner; cloud account owner authorizes scans. |
| Limitations | A repository does not grant cloud access or establish compliance. |

Use least-privilege read-only IAM permissions and document account, region, profile, and resource scope before scanning. Keep credentials out of commits, logs, fixtures, and reports.
