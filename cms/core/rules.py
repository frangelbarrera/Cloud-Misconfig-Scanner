import yaml
from pathlib import Path

class Rule:
    def __init__(self, rule_id, title, severity, description, remediation):
        self.id = rule_id
        self.title = title
        self.severity = severity
        self.description = description
        self.remediation = remediation

def load_rules(path: str):
    """Carga reglas desde un archivo YAML y devuelve una lista de Rule."""
    rules = []
    file_path = Path(path)
    if not file_path.exists():
        return rules
    with open(file_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or []
        for item in data:
            rules.append(Rule(
                rule_id=item.get("id"),
                title=item.get("title"),
                severity=item.get("severity"),
                description=item.get("description"),
                remediation=item.get("remediation")
            ))
    return rules
