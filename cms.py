import argparse, sys
from cms.core.reporter import print_text, print_json
from cms.core.html_reporter import generate_html_report
from cms.providers.aws_s3 import AwsS3Scanner
from cms.providers.azure_blob import AzureBlobScanner
from cms.providers.gcp_storage import GcpStorageScanner

def main():
    p = argparse.ArgumentParser(prog="Cloud Misconfig Scanner")
    p.add_argument("--provider", required=True, choices=["aws", "azure", "gcp", "all"])
    p.add_argument("--profile", help="Provider profile/credentials name (e.g., AWS profile)")
    p.add_argument("--region", help="Default region if applicable")
    p.add_argument("--targets", help="Comma-separated bucket/container names")
    p.add_argument("--format", default="text", choices=["text", "json", "html"])
    p.add_argument("--connection-string", help="Azure Blob connection string")
    p.add_argument("--gcp-credentials", help="Path to GCP credentials JSON")
    args = p.parse_args()

    targets = args.targets.split(",") if args.targets else None
    results = []

    if args.provider in ("aws", "all"):
        results.append(AwsS3Scanner(profile=args.profile, region=args.region).scan(targets))
    if args.provider in ("azure", "all"):
        results.append(AzureBlobScanner(connection_string=args.connection_string).scan(targets))
    if args.provider in ("gcp", "all"):
        results.append(GcpStorageScanner(credentials_path=args.gcp_credentials).scan(targets))

    # Merge results
    all_findings = []
    for r in results:
        all_findings.extend(r.findings)

    # Salida según formato
    wrapper = type("ResultWrapper", (), {"findings": all_findings})()
    if args.format == "json":
        print_json(wrapper)
    elif args.format == "html":
        generate_html_report(wrapper, "report.html")
    else:
        print_text(wrapper)

if __name__ == "__main__":
    sys.exit(main())
