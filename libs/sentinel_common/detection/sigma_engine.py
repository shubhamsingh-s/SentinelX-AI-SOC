"""Layer 1: Sigma Rule Detection Engine."""

from typing import Any

import yaml

from sentinel_common.detection.parsers import ParsedLogEvent


class SigmaRule:
    """Sigma rule specification model."""

    def __init__(
        self,
        rule_id: str,
        title: str,
        level: str,
        selection: dict[str, Any],
        description: str = "",
        tags: list[str] | None = None,
    ) -> None:
        self.rule_id = rule_id
        self.title = title
        self.level = level  # low, medium, high, critical
        self.selection = selection
        self.description = description
        self.tags = tags or []

    @classmethod
    def from_yaml(cls, yaml_content: str) -> "SigmaRule":
        """Parse Sigma rule object from YAML string."""
        data = yaml.safe_load(yaml_content)
        detection = data.get("detection", {})
        selection = detection.get("selection", {})
        return cls(
            rule_id=data.get("id", "sigma-001"),
            title=data.get("title", "Untitled Sigma Rule"),
            level=data.get("level", "medium"),
            selection=selection,
            description=data.get("description", ""),
            tags=data.get("tags", []),
        )


class SigmaEngine:
    """Sigma detection rule evaluator."""

    def __init__(self, rules: list[SigmaRule] | None = None) -> None:
        self.rules: list[SigmaRule] = rules or []

    def add_rule(self, rule: SigmaRule) -> None:
        """Register a Sigma rule into the engine."""
        self.rules.append(rule)

    def evaluate(self, event: ParsedLogEvent) -> list[SigmaRule]:
        """Evaluate event against registered Sigma rules returning matched rules."""
        matched_rules: list[SigmaRule] = []
        event_dict = event.to_dict()

        for rule in self.rules:
            if self._matches_selection(event, event_dict, rule.selection):
                matched_rules.append(rule)
        return matched_rules

    def _matches_selection(self, event: ParsedLogEvent, event_dict: dict[str, Any], selection: dict[str, Any]) -> bool:
        """Verify if event satisfies selection condition dictionary."""
        for field, expected in selection.items():
            if field == "raw_payload|contains":
                if isinstance(expected, list):
                    if not any(item.lower() in event.raw_payload.lower() for item in expected):
                        return False
                elif expected.lower() not in event.raw_payload.lower():
                    return False
            elif field in event_dict:
                val = event_dict[field]
                if val != expected:
                    return False
        return True
