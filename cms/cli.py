"""Cloud Misconfig Scanner - CLI implementation.

This module hosts the real CLI logic so that it can be exposed both as
``python cms.py`` (legacy entry point) and as the
``cloud-misconfig-scanner`` console script declared in ``pyproject.toml``.
"""
from __future__ import annotations

import argparse
import sys

from cms.core.html_reporter import generate_html_report
from cms.core.models import ScanResult
from cms.core.reporter import filter_by_severity, print_json, print_text
from cms.providers.aws_s3 import AwsS3Scanner
from cms.providers.azure_blob import AzureBlobScanner
from cms.providers.gcp_storage import GcpStorageScanner

# Exit codes follow the conventions used by tools like Prowler / Trivy:
#   0 = no findings (clean posture)
#   1 = findings detected
#   2 = usage error (handled by argparse)
#   3 = scanner runtime error
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_RUNTIME = 3


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloud-misconfig-scanner",
        description=(
            "Detect misconfigurations in cloud storage services. "
            "AWS S3 runs in real mode by default; Azure and GCP run in "
            "simulated mode until their SDKs are wired in."
        ),
    )
    p.add_argument(
        "--provider",
        required=True,
        choices=["aws", "azure", "gcp", "all"],
        help="Cloud provider to scan.",
    )
    p.add_argument(
        "--profile",
        help="Provider profile/credentials name (e.g., AWS profile).",
    )
    p.add_argument(
        "--region",
        help="Default region if applicable (defaults to us-east-1 for AWS).",
    )
    p.add_argument(
        "--targets",
        help="Comma-separated bucket/container names to narrow the scan.",
    )
    p.add_argument(
        "--format",
        default="text",
        choices=["text", "json", "html"],
        help="Output format (default: text).",
    )
    p.add_argument(
        "-o",
        "--output",
        help=(
            "Output file path for HTML reports. If omitted, a timestamped "
            "report_*.html is written. Ignored for text/json."
        ),
    )
    p.add_argument(
        "--severity",
        help="Minimum severity to report (LOW, MEDIUM, HIGH, CRITICAL).",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    )
    p.add_argument(
        "--simulated",
        action="store_true",
        help=(
            "Force simulated mode (skip real API calls). Without this flag, "
            "AWS S3 auto-detects credentials and runs in real mode by default."
        ),
    )
    p.add_argument(
        "--connection-string",
        help="Azure Blob connection string (enables real Azure mode when set).",
    )
    p.add_argument(
        "--gcp-credentials",
        help="Path to GCP credentials JSON (enables real GCP mode when set).",
    )
    return p


def _scan_all(args: argparse.Namespace) -> ScanResult:
    targets = (
        [t.strip() for t in args.targets.split(",") if t.strip()]
        if args.targets
        else None
    )
    merged = ScanResult()

    if args.provider in ("aws", "all"):
        scanner = AwsS3Scanner(
            profile=args.profile,
            region=args.region,
            simulated=True if args.simulated else None,
        )
        merged.findings.extend(scanner.scan(targets).findings)

    if args.provider in ("azure", "all"):
        scanner = AzureBlobScanner(connection_string=args.connection_string)
        merged.findings.extend(scanner.scan(targets).findings)

    if args.provider in ("gcp", "all"):
        scanner = GcpStorageScanner(credentials_path=args.gcp_credentials)
        merged.findings.extend(scanner.scan(targets).findings)

    return merged


def _emit(args: argparse.Namespace, results: ScanResult) -> None:
    if args.format == "json":
        print_json(results, min_severity=args.severity)
    elif args.format == "html":
        generate_html_report(results, output_path=args.output)
    else:
        print_text(results, min_severity=args.severity)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        results = _scan_all(args)
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[ERROR] Scanner runtime error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME

    _emit(args, results)

    visible = filter_by_severity(results, args.severity)
    return EXIT_FINDINGS if visible else EXIT_CLEAN
