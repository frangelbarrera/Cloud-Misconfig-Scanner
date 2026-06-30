"""YAML rule loader.

Rules are authored in ``cms/checks/<provider>_<service>_rules.yaml`` and
parsed into :class:`Rule` instances by :func:`load_rules`. The registry
provides O(1) lookup by rule id so that provider scanners can keep their
finding logic inline while still sourcing the human-readable metadata
(title, description, remediation, severity) from the YAML file.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Rule:
    """A single misconfiguration rule definition."""

    id: str
    title: str
    severity: str
    description: str
    remediation: str


class RuleRegistry:
    """In-memory lookup table of rules keyed by rule id."""

    def __init__(self, rules: list[Rule] | None = None):
        self._by_id: dict[str, Rule] = {}
        for rule in rules or []:
            self.add(rule)

    def add(self, rule: Rule) -> None:
        if not rule or not rule.id:
            return
        self._by_id[rule.id] = rule

    def get(self, rule_id: str) -> Rule | None:
        return self._by_id.get(rule_id)

    def require(self, rule_id: str) -> Rule:
        """Return the rule or raise KeyError with a helpful message."""
        try:
            return self._by_id[rule_id]
        except KeyError as exc:
            raise KeyError(
                f"Rule '{rule_id}' is not defined in the loaded YAML. "
                f"Available rules: {sorted(self._by_id)}"
            ) from exc

    def all(self) -> list[Rule]:
        return list(self._by_id.values())

    def __len__(self) -> int:
        return len(self._by_id)

    def __iter__(self):
        return iter(self._by_id.values())

    def __contains__(self, rule_id: str) -> bool:  # pragma: no cover - trivial
        return rule_id in self._by_id


def load_rules(path: str) -> list[Rule]:
    """Load rules from a YAML file and return a list of :class:`Rule`.

    Returns an empty list when the file does not exist so that callers can
    rely on the returned value without an extra existence check.
    """
    file_path = Path(path)
    if not file_path.exists():
        return []

    with open(file_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or []

    rules: list[Rule] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rules.append(
            Rule(
                id=item.get("id") or "",
                title=item.get("title") or "",
                severity=(item.get("severity") or "MEDIUM").upper(),
                description=item.get("description") or "",
                remediation=item.get("remediation") or "",
            )
        )
    return rules


def load_registry(path: str) -> RuleRegistry:
    """Convenience wrapper: load rules and wrap them in a registry."""
    return RuleRegistry(load_rules(path))
