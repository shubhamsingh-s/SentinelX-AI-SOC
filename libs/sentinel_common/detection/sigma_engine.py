"""Layer 1: YAML Sigma-Style Rule Loader and Matcher."""

from __future__ import annotations

import re
from typing import Any

import yaml

from sentinel_common.detection.parsers import ParsedLogEvent


class SigmaRule:
    """Sigma rule specification model with YAML loading and matching logic."""

    def __init__(
        self,
        rule_id: str,
        title: str,
        level: str,
        selection: dict[str, Any] | None = None,
        detection: dict[str, Any] | None = None,
        description: str = "",
        tags: list[str] | None = None,
        raw_yaml: str = "",
    ) -> None:
        self.rule_id = rule_id
        self.title = title
        self.level = level.lower()  # low, medium, high, critical
        self.detection = detection or {}
        if selection is not None:
            self.selection = selection
        else:
            self.selection = self.detection.get("selection", {})
        self.description = description
        self.tags = tags or []
        self.raw_yaml = raw_yaml

    @classmethod
    def from_yaml(cls, yaml_content: str) -> SigmaRule:
        """Parse Sigma rule object from YAML string."""
        data = yaml.safe_load(yaml_content)
        if not isinstance(data, dict):
            raise ValueError("Invalid YAML content: must be a mapping/dictionary")
        return cls.from_dict(data, raw_yaml=yaml_content)

    @classmethod
    def from_dict(cls, data: dict[str, Any], raw_yaml: str = "") -> SigmaRule:
        """Create SigmaRule from dictionary."""
        detection = data.get("detection", {})
        selection = detection.get("selection", {})
        return cls(
            rule_id=str(data.get("id", "sigma-001")),
            title=str(data.get("title", "Untitled Sigma Rule")),
            level=str(data.get("level", "medium")),
            selection=selection,
            detection=detection,
            description=str(data.get("description", "")),
            tags=list(data.get("tags", [])),
            raw_yaml=raw_yaml,
        )

    def matches(self, event: ParsedLogEvent | dict[str, Any]) -> bool:
        """Check if an event matches this Sigma rule."""
        event_dict = event.to_dict() if isinstance(event, ParsedLogEvent) else event
        raw_payload = str(event_dict.get("raw_payload", ""))

        condition = self.detection.get("condition")
        if not condition:
            # Default behavior: match selection block
            return self._matches_selection_dict(event_dict, raw_payload, self.selection)

        # Handle condition expressions e.g. "selection", "selection and not filter", "selection_1 or selection_2"
        return self._evaluate_condition(condition, event_dict, raw_payload)

    def _matches_selection_dict(self, event_dict: dict[str, Any], raw_payload: str, selection: dict[str, Any]) -> bool:
        """Verify if event satisfies a single selection block."""
        if not selection:
            return False

        for field_spec, expected in selection.items():
            if not self._match_field(field_spec, expected, event_dict, raw_payload):
                return False
        return True

    def _match_field(self, field_spec: str, expected: Any, event_dict: dict[str, Any], raw_payload: str) -> bool:
        """Evaluate a single field specification (e.g. 'raw_payload|contains')."""
        if "|" in field_spec:
            field_name, modifier = field_spec.split("|", 1)
        else:
            field_name, modifier = field_spec, "exact"

        # Resolve field value from event_dict or extra_fields
        if field_name == "raw_payload":
            actual_val = raw_payload
        elif field_name in event_dict:
            actual_val = event_dict[field_name]
        elif "extra_fields" in event_dict and isinstance(event_dict["extra_fields"], dict):
            actual_val = event_dict["extra_fields"].get(field_name)
        else:
            actual_val = None

        if actual_val is None:
            return False

        actual_str = str(actual_val).lower()

        if modifier == "contains":
            if isinstance(expected, list):
                return any(str(item).lower() in actual_str for item in expected)
            return str(expected).lower() in actual_str

        if modifier == "startswith":
            if isinstance(expected, list):
                return any(actual_str.startswith(str(item).lower()) for item in expected)
            return actual_str.startswith(str(expected).lower())

        if modifier == "endswith":
            if isinstance(expected, list):
                return any(actual_str.endswith(str(item).lower()) for item in expected)
            return actual_str.endswith(str(expected).lower())

        if modifier in ("re", "regex"):
            try:
                pattern = re.compile(str(expected), re.IGNORECASE)
                return bool(pattern.search(str(actual_val)))
            except re.error:
                return False

        # Default exact match
        if isinstance(expected, list):
            return any(str(actual_val).lower() == str(item).lower() for item in expected)
        return str(actual_val).lower() == str(expected).lower()

    def _evaluate_condition(self, condition: str, event_dict: dict[str, Any], raw_payload: str) -> bool:
        """Evaluate condition string referencing detection blocks."""
        tokens = condition.split()
        if len(tokens) == 1 and tokens[0] in self.detection:
            return self._matches_selection_dict(event_dict, raw_payload, self.detection[tokens[0]])

        # Basic parser for "selection and not filter" or "a or b"
        if "and not" in condition:
            parts = condition.split("and not")
            pos_block = parts[0].strip()
            neg_block = parts[1].strip()
            pos_matches = self._matches_selection_dict(event_dict, raw_payload, self.detection.get(pos_block, {}))
            neg_matches = self._matches_selection_dict(event_dict, raw_payload, self.detection.get(neg_block, {}))
            return pos_matches and not neg_matches

        if "or" in condition:
            blocks = [b.strip() for b in condition.split("or")]
            return any(self._matches_selection_dict(event_dict, raw_payload, self.detection.get(b, {})) for b in blocks)

        if "and" in condition:
            blocks = [b.strip() for b in condition.split("and")]
            return all(self._matches_selection_dict(event_dict, raw_payload, self.detection.get(b, {})) for b in blocks)

        # Fallback to selection block
        return self._matches_selection_dict(event_dict, raw_payload, self.selection)

    def dry_run_test(self, event: ParsedLogEvent | dict[str, Any]) -> dict[str, Any]:
        """Perform a dry-run test returning match result and diagnostic details."""
        event_dict = event.to_dict() if isinstance(event, ParsedLogEvent) else event
        matched = self.matches(event)
        return {
            "matched": matched,
            "rule_id": self.rule_id,
            "title": self.title,
            "level": self.level,
            "description": self.description,
            "tags": self.tags,
            "selection": self.selection,
            "evaluated_event_keys": list(event_dict.keys()),
        }


class SigmaEngine:
    """Sigma detection rule evaluator across a collection of rules."""

    def __init__(self, rules: list[SigmaRule] | None = None) -> None:
        self.rules: list[SigmaRule] = rules or []

    def add_rule(self, rule: SigmaRule) -> None:
        """Register a Sigma rule into the engine."""
        self.rules.append(rule)

    def evaluate(self, event: ParsedLogEvent | dict[str, Any]) -> list[SigmaRule]:
        """Evaluate event against registered Sigma rules returning matched rules."""
        matched_rules: list[SigmaRule] = []
        for rule in self.rules:
            if rule.matches(event):
                matched_rules.append(rule)
        return matched_rules
