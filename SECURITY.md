# Security Policy — Cloud-Misconfig-Scanner

This repository (`frangelbarrera/Cloud-Misconfig-Scanner`) is **actively
maintained** — the latest commit landed on `main` on 2026-06-30 (Phase 2:
real AWS S3 scanning). It is a Python CLI that detects misconfigurations in
cloud storage services. AWS S3 is fully supported via `boto3`; Azure Blob
and GCP Storage run in **simulated mode** only (real SDK integration is on
the roadmap).

Because this tool is itself a security product, we hold it to a higher
standard: a bug that silently misses a public bucket is arguably worse
than no scanner at all.

## Supported Versions

| Version | Branch / Tag | Supported          | Notes                                  |
|---------|--------------|--------------------|----------------------------------------|
| 0.2.0   | `main`       | :white_check_mark: | Current development branch             |
| < 0.2.0 | n/a          | :x:                | Pre-Phase-2 (simulated-only); unsupported |

The project has not cut git tags or GitHub Releases yet; users pin by
commit SHA or the mutable `main` branch. Until a `v0.2.0` tag exists,
only the latest commit on `main` receives security fixes.

## Reporting a Vulnerability

Report security issues **privately** before opening a public issue.

- **Email:** `frangelrcbarrera@gmail.com`
- **Subject line:** `[SECURITY] Cloud-Misconfig-Scanner — <short summary>`

Include: (1) affected file(s) and line number(s) (e.g.
`cms/providers/aws_s3.py:199`); (2) a minimal reproduction (`python cms.py
--provider aws ...` preferred); (3) Python, `boto3`/`botocore`, and OS
versions; (4) real AWS or `--simulated` mode; (5) impact; (6) suggested
remediation, if any.

**Do not include real AWS credentials in your report** — redact them or use
`--simulated` mode. You should receive an acknowledgement within **3
business days**; if not, please follow up once.

## Response Timeline

| Severity | First response | Triage + fix plan | Patch release target |
|----------|----------------|--------------------|----------------------|
| Critical | ≤ 3 business days | ≤ 7 days           | ≤ 30 days            |
| High     | ≤ 3 business days | ≤ 14 days          | ≤ 60 days            |
| Medium   | ≤ 5 business days | ≤ 30 days          | Next minor release   |
| Low      | ≤ 7 business days | Best-effort        | Next minor release   |

These SLAs are targets, not contractual guarantees — this is a small,
volunteer-maintained project. We will keep reporters informed at each step.

## Scope

### In scope

- The `cms/` Python package (`cms/cli.py`, `cms/core/*`, `cms/providers/*`).
- The `cms.py` legacy entry point and the `cloud-misconfig-scanner`
  console script declared in `pyproject.toml`.
- The YAML rule files under `cms/checks/`.
- The HTML/JSON/text reporters (`cms/core/reporter.py`,
  `cms/core/html_reporter.py`).
- The GitHub Actions workflow at `.github/workflows/ci.yml`.
- The IAM policy documents under `docs/iam/`.

### Out of scope

- Vulnerabilities in third-party dependencies (`boto3`, `botocore`,
  `pyyaml`, `pytest`, `moto`, `ruff`) — report those upstream.
- Issues requiring privileged access to the maintainer's GitHub/PyPI
  account or build infrastructure.
- Findings from running the scanner against accounts you do not own or are
  not authorised to assess. The scanner is read-only, but unauthorised use
  against third-party AWS accounts may breach computer-misuse law
  (see **Legal Framework** below).
- Theoretical DoS against AWS APIs by running the scanner at extreme scale.

### Known limitations (not vulnerabilities)

These are honest limitations of the current release; please don't report
them as security issues:

- **Azure Blob and GCP Storage are simulated-only.** Even when
  `--connection-string` or `--gcp-credentials` is supplied, `scan()`
  returns no findings for those providers (`cms/providers/azure_blob.py:62`,
  `cms/providers/gcp_storage.py:62`). Real SDK integration is roadmap.
- **Dependencies are lower-bound pinned only** (`boto3>=1.34.57`,
  `botocore>=1.34.57`, `pyyaml>=6.0.1`). We do not yet upper-bound or
  hash-pin dependencies.
- **`--connection-string` passes the Azure connection string on the command
  line**, visible to other users via `ps`/`/proc`. Prefer env vars when
  real Azure mode ships.
- **Non-existent buckets in `--targets` produce false-positive findings**
  for every check, because each per-bucket helper catches
  `botocore.exceptions.ClientError` and returns the "misconfigured"
  default.
- **No rate limiting or retry/backoff** on AWS API calls. Large accounts
  may hit S3 throttling.
- **The IAM policy document** at `docs/iam/aws_least_privilege.json` lists
  `s3:GetAccountPublicAccessBlock`, but the scanner actually calls
  `s3control:GetPublicAccessBlock` (`cms/providers/aws_s3.py:199`). The
  README has the correct permission. We are fixing the JSON doc.
- **CI actions are pinned to major version**, not commit SHA, and
  `pip install --upgrade pip` is non-reproducible. Supply-chain hardening
  is on the roadmap.

## Safe Harbor

We will not pursue legal action against good-faith security research that:

1. Targets only accounts, buckets, and infrastructure you own or are
   explicitly authorised to test.
2. Does not exfiltrate, modify, or destroy data, or degrade availability
   (no aggressive scanning, no DoS).
3. Reports findings privately first and gives us a reasonable window
   (90 days for Critical/High) before public disclosure.
4. Avoids testing on production AWS accounts — use a sandbox account.

## Legal Framework

This policy is offered in the spirit of coordinated disclosure and is
consistent with the following international instruments:

- **United States** — Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030.
  The U.S. Department of Justice's 2022 charging policy narrows CFAA
  enforcement against good-faith researchers.
- **European Union** — Directive 2013/40/EU on attacks against information
  systems.
- **Council of Europe** — Convention on Cybercrime (Budapest Convention,
  2001), Articles 2–3 (illegal access and system interference).
- **United Kingdom** — Computer Misuse Act 1990 (CMA), as amended.

This list is informational and non-exhaustive. Researchers are responsible
for complying with the laws of their jurisdiction and the jurisdiction of
any system they touch. Nothing here is a waiver of legal rights; it is a
good-faith statement of how the maintainer responds to responsible disclosure.

## Known Security Considerations

The scanner is **read-only** at the AWS API level: the IAM policy in
`docs/iam/aws_least_privilege.json` grants only `s3:List*`, `s3:Get*`, and
`sts:GetCallerIdentity` (no `Put*`, `Delete*`, or write actions). Even so,
users should be aware of:

- **Dual-use nature.** With stolen AWS credentials, the scanner could
  enumerate buckets, ACLs, and policies of a victim account. This is
  inherent to any cloud security tool. We assume the operator has
  legitimate access to the target account.
- **AWS credentials handling.** The scanner never logs credentials. It
  uses the standard boto3 credential chain (`~/.aws/credentials`,
  `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE`). When no
  credentials are detected, it auto-falls-back to `--simulated` mode and
  emits an `AWS-S3-SCAN-WARNING` LOW finding
  (`cms/providers/aws_s3.py:112`). The `.gitignore` excludes `.aws/` and
  `*.env`.
- **HTML report XSS.** All finding fields rendered by
  `cms/core/html_reporter.py` pass through `html.escape()` before template
  insertion. A regression test
  (`tests/test_html_reporter.py::test_html_report_escapes_xss_payload`)
  asserts `<script>` payloads in rule IDs, titles, descriptions,
  remediations, and resource names are escaped. If you find a path that
  bypasses `_esc()`, please report it.
- **YAML rule loading.** Rule files are parsed with `yaml.safe_load()`
  (`cms/core/rules.py:78`), not `yaml.load()`. Custom rule files supplied
  via `rules_path=` are also safe-loaded.
- **No `subprocess`, `eval`, `exec`, `os.system`, or `verify=False`**
  appears anywhere in the `cms/` package or test suite.
- **CI permissions** are scoped to `contents: read`
  (`.github/workflows/ci.yml:9-10`). Coverage artifacts are uploaded only
  on `if: always()`.

## Contact

- **Security reports:** `frangelrcbarrera@gmail.com`
- **General issues / PRs:** https://github.com/frangelbarrera/Cloud-Misconfig-Scanner/issues

If you contribute a verified security fix, you will be credited in the
release notes and commit message unless you ask to remain anonymous.
Thank you for helping make cloud storage a little less misconfigured.
