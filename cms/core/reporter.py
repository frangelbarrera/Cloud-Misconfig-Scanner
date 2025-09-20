import json
from cms.core.models import ScanResult

def print_text(results: ScanResult):
    if not results.findings:
        print("No findings. Posture looks OK.")
        return
    print("Findings:")
    for f in results.findings:
        print(f"- [{f.severity}] {f.rule_id} | {f.title} -> {f.resource.provider}:{f.resource.name}")

def print_json(results: ScanResult):
    print(json.dumps(
        [f.__dict__ | {"resource": f.resource.__dict__} for f in results.findings],
        indent=2
    ))
