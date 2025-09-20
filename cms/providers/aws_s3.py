import os
import boto3, botocore
from cms.core.models import Resource, Finding, ScanResult

class AwsS3Scanner:
    def __init__(self, profile=None, region=None):
        self.profile = profile
        self.region = region

        # Si no hay credenciales AWS, activamos modo simulado
        creds_path = os.path.expanduser("~/.aws/credentials")
        if not os.path.exists(creds_path):
            self.simulated = True
        else:
            self.simulated = False
            self.session = boto3.Session(profile_name=profile) if profile else boto3.Session()
            self.s3 = self.session.client("s3")
            self.s3control = self.session.client("s3control", region_name="us-east-1")
            self.sts = self.session.client("sts")
            self.account = self.sts.get_caller_identity()["Account"]

    def _resource(self, name, meta=None):
        return Resource(provider="aws", service="s3",
                        account=getattr(self, "account", "000000000000"),
                        region=self.region or "us-east-1",
                        name=name, meta=meta or {})

    def scan(self, targets=None) -> ScanResult:
        res = ScanResult()

        # --- MODO SIMULADO ---
        if self.simulated:
            fake_resource = self._resource("fake-bucket")
            res.add(Finding(
                "TEST-RULE",
                "Test finding (simulated)",
                "HIGH",
                "Descripción de prueba para validar flujo sin AWS.",
                "No requiere acción, es solo una prueba.",
                fake_resource,
                {"simulated": True}
            ))
            return res

        # --- MODO REAL ---
        buckets = [{"Name": b} for b in targets] if targets else self.s3.list_buckets()["Buckets"]

        try:
            account_bpa = self.s3control.get_public_access_block(AccountId=self.account)["PublicAccessBlockConfiguration"]
        except botocore.exceptions.ClientError:
            account_bpa = {}

        for b in buckets:
            name = b["Name"] if isinstance(b, dict) else b
            r = self._resource(name)

            try:
                bpa = self.s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            except botocore.exceptions.ClientError:
                bpa = {}

            try:
                enc = self.s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]
                sse = enc.get("SSEAlgorithm", "none")
            except botocore.exceptions.ClientError:
                sse = "none"

            try:
                ver = self.s3.get_bucket_versioning(Bucket=name).get("Status") or "disabled"
            except botocore.exceptions.ClientError:
                ver = "unknown"

            # --- Findings ---
            if not all(account_bpa.get(k, False) for k in account_bpa):
                res.add(Finding("AWS-S3-ACCOUNT-BPA", "Account BPA not fully enabled", "MEDIUM",
                    "Enable all four S3 Account Block Public Access settings.",
                    "Set BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets to true.",
                    r, {"account_bpa": account_bpa}))

            if bpa and not all(bpa.values()):
                res.add(Finding("AWS-S3-BUCKET-BPA", "Bucket BPA has disabled flags", "HIGH",
                    "Enable all four Bucket Public Access Block settings.",
                    "Set bucket-level BPA to block and restrict public access.",
                    r, {"bucket_bpa": bpa}))

            if sse == "none":
                res.add(Finding("AWS-S3-ENCRYPTION", "No default encryption", "HIGH",
                    "Enable default encryption (SSE-S3 or SSE-KMS).",
                    "Set ServerSideEncryptionConfiguration.",
                    r, {"sse": sse}))

            if ver in ("disabled", "Suspended"):
                res.add(Finding("AWS-S3-VERSIONING", "Versioning not enabled", "HIGH",
                    "Enable versioning to support recovery and ransomware resilience.",
                    "Set Versioning=Enabled.",
                    r, {"versioning": ver}))

        return res
