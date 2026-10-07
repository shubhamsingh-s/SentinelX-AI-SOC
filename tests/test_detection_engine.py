"""Tests for Threat Detection Engine:

- Sigma YAML rule loader and matcher (contains, startswith, endswith, regex, condition)
- Threshold rules with Redis sliding windows (ZADD, ZREMRANGEBYSCORE, ZCARD)
- Redis IOC threat intel cache lookup
- ML Isolation Forest UEBA anomaly scorer & composite 0-100 risk score formula
- Detection pipeline, Alert entity creation, and publishing to Redis Stream alerts:new
- Redis Consumer Group worker reading events:raw with XREADGROUP and XACK
- Detection Rules CRUD API endpoints (POST, GET, PUT, DELETE)
- Rules dry-run test endpoint /rules/{id}/test
"""

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient

from sentinel_common.detection.ioc_engine import IOCEngine
from sentinel_common.detection.ml_engine import RiskScorer, UEBAAnomalyDetector
from sentinel_common.detection.parsers import LogParser, ParsedLogEvent
from sentinel_common.detection.pipeline import ThreatDetectionPipeline
from sentinel_common.detection.sigma_engine import SigmaEngine, SigmaRule
from sentinel_common.detection.threshold_engine import ThresholdEngine, ThresholdRule
from services.detection_engine.app.services.consumer import EventDetectionConsumer


class InMemoryMockRedis:
    """In-memory Redis mock supporting Strings, ZSETs, Streams, and Consumer Groups."""

    def __init__(self) -> None:
        self.store: dict[str, Any] = {}
        self.zsets: dict[str, list[tuple[str, float]]] = {}
        self.streams: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        self.groups: set[tuple[str, str]] = set()
        self.acks: list[tuple[str, str, str]] = []

    async def get(self, key: str) -> Any:
        return self.store.get(key)

    async def set(self, key: str, val: Any, ex: int | None = None) -> bool:
        self.store[key] = val
        return True

    async def zremrangebyscore(self, key: str, min_s: str, max_s: float | str) -> int:
        if key not in self.zsets:
            return 0
        max_val = float(max_s) if max_s != "-inf" else float("-inf")
        remaining = []
        removed = 0
        for member, score in self.zsets[key]:
            if score <= max_val:
                removed += 1
            else:
                remaining.append((member, score))
        self.zsets[key] = remaining
        return removed

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        if key not in self.zsets:
            self.zsets[key] = []
        for member, score in mapping.items():
            self.zsets[key].append((member, float(score)))
        return len(mapping)

    async def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, []))

    async def expire(self, key: str, ttl: int) -> bool:
        return True

    async def xadd(self, stream: str, payload: dict[str, Any]) -> str:
        if stream not in self.streams:
            self.streams[stream] = []
        msg_id = f"1700000000000-{len(self.streams[stream])}"
        self.streams[stream].append((msg_id, payload))
        return msg_id

    async def xgroup_create(self, name: str, groupname: str, id: str = "$", mkstream: bool = False) -> bool:
        self.groups.add((name, groupname))
        return True

    async def xreadgroup(
        self,
        groupname: str,
        consumername: str,
        streams: dict[str, str],
        count: int = 10,
        block: int = 1000,
    ) -> list[tuple[str, list[tuple[str, dict[str, Any]]]]]:
        res = []
        for sname in streams:
            msgs = self.streams.get(sname, [])[:count]
            if msgs:
                res.append((sname, msgs))
        return res

    async def xack(self, stream: str, groupname: str, message_id: str) -> int:
        self.acks.append((stream, groupname, message_id))
        return 1


# ---------------------------------------------------------------------------
# 1. Log Parsers
# ---------------------------------------------------------------------------
def test_log_parsers() -> None:
    """Test Syslog, CloudTrail, and VPC Flow Log parsing."""
    syslog_msg = (
        "<134>1 2026-10-07T00:00:00Z web01 sshd 1234 - - Failed password for invalid user"
        " admin from 192.168.1.100 port 54321 ssh2"
    )
    parsed_syslog = LogParser.parse_syslog(syslog_msg)
    assert parsed_syslog.source_type == "syslog"
    assert parsed_syslog.source_ip == "192.168.1.100"
    assert parsed_syslog.username == "admin"

    ct_payload = {
        "Records": [
            {
                "eventName": "ConsoleLogin",
                "sourceIPAddress": "10.0.0.99",
                "userIdentity": {"userName": "compromised_user"},
                "eventSource": "signin.amazonaws.com",
            }
        ]
    }
    parsed_ct = LogParser.parse_cloudtrail(ct_payload)
    assert len(parsed_ct) == 1
    assert parsed_ct[0].event_name == "ConsoleLogin"
    assert parsed_ct[0].source_ip == "10.0.0.99"
    assert parsed_ct[0].username == "compromised_user"

    vpc_line = "2 123456789012 eni-01235678 192.168.1.5 10.0.0.1 443 49152 6 10 8400 1600000000 1600000060 REJECT OK"
    parsed_vpc = LogParser.parse_vpc_flow(vpc_line)
    assert parsed_vpc.source_ip == "192.168.1.5"
    assert parsed_vpc.destination_ip == "10.0.0.1"
    assert "REJECT" in parsed_vpc.event_name


# ---------------------------------------------------------------------------
# 2. Sigma Rule Loader & Matcher (Advanced Modifiers & Condition)
# ---------------------------------------------------------------------------
def test_sigma_engine_modifiers_and_condition() -> None:
    """Test Sigma modifiers (contains, startswith, regex) and condition logic."""
    rule_yaml = """
title: Detect Advanced PowerShell Invocation
id: sigma-ps-001
level: critical
tags:
  - attack.execution
  - attack.t1059.001
detection:
  selection_cmd:
    raw_payload|contains:
      - "powershell.exe -enc"
      - "pwsh -encodedcommand"
  selection_ip:
    source_ip|startswith: "192.168."
  condition: selection_cmd and selection_ip
"""
    rule = SigmaRule.from_yaml(rule_yaml)
    assert rule.level == "critical"
    assert "attack.execution" in rule.tags

    # Matching event
    match_event = {
        "raw_payload": "C:\\Windows\\System32\\powershell.exe -enc SQBFA...",
        "source_ip": "192.168.1.42",
        "username": "admin",
    }
    assert rule.matches(match_event) is True

    # Non-matching event (different IP prefix)
    non_match_event = {
        "raw_payload": "powershell.exe -enc SQBFA...",
        "source_ip": "10.0.0.5",
    }
    assert rule.matches(non_match_event) is False

    # Regex modifier test
    regex_rule_yaml = """
title: Detect SQL Injection Attempt
id: sigma-sqli-001
level: high
detection:
  selection:
    raw_payload|re: '(?i)union\\s+select.*from'
"""
    regex_rule = SigmaRule.from_yaml(regex_rule_yaml)
    assert regex_rule.matches({"raw_payload": "GET /item?id=1 UNION SELECT password FROM users"}) is True
    assert regex_rule.matches({"raw_payload": "GET /item?id=123 normal query"}) is False

    # Dry-run test helper
    dry_run = regex_rule.dry_run_test({"raw_payload": "UNION SELECT 1 FROM dual"})
    assert dry_run["matched"] is True
    assert dry_run["rule_id"] == "sigma-sqli-001"


# ---------------------------------------------------------------------------
# 3. Threshold Rules with Redis Sliding Windows
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_threshold_engine_sliding_window() -> None:
    """Test sliding window event counting, threshold violation, and expired item purging."""
    mock_redis = InMemoryMockRedis()
    rule = ThresholdRule(
        rule_id="th-brute-force",
        title="Excessive Failed Logins",
        severity="high",
        window_seconds=60,
        threshold=3,
        group_by="source_ip",
        event_filter={"event_name": "FailedLogin"},
    )
    engine = ThresholdEngine([rule])

    event = {
        "event_name": "FailedLogin",
        "source_ip": "198.51.100.5",
        "username": "victim",
    }

    # Event 1: Count = 1 (Below threshold)
    matches_1 = await engine.evaluate(mock_redis, event, tenant_id="tenant-1")
    assert len(matches_1) == 0

    # Event 2: Count = 2 (Below threshold)
    matches_2 = await engine.evaluate(mock_redis, event, tenant_id="tenant-1")
    assert len(matches_2) == 0

    # Event 3: Count = 3 (Threshold met!)
    matches_3 = await engine.evaluate(mock_redis, event, tenant_id="tenant-1")
    assert len(matches_3) == 1
    assert matches_3[0].count == 3
    assert matches_3[0].threshold == 3
    assert matches_3[0].group_by_value == "198.51.100.5"

    # Event with different IP does not affect the first IP's bucket
    event_diff_ip = {"event_name": "FailedLogin", "source_ip": "198.51.100.99"}
    matches_diff = await engine.evaluate(mock_redis, event_diff_ip, tenant_id="tenant-1")
    assert len(matches_diff) == 0


# ---------------------------------------------------------------------------
# 4. Redis IOC Cache Lookup
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_redis_ioc_cache_lookup() -> None:
    """Test caching threat intel indicators in Redis and matching events."""
    mock_redis = InMemoryMockRedis()
    ioc_engine = IOCEngine()

    # Store known malicious IP in Redis threat cache
    await IOCEngine.set_redis_ioc(
        mock_redis,
        ioc_type="ip",
        ioc_value="203.0.113.195",
        threat_name="LockBit C2 Server",
        confidence=98,
    )

    clean_event = ParsedLogEvent(
        source_type="syslog",
        timestamp=datetime.now(UTC),
        event_name="TRAFFIC",
        source_ip="8.8.8.8",
    )
    clean_matches = await ioc_engine.evaluate_redis(mock_redis, clean_event)
    assert len(clean_matches) == 0

    malicious_event = ParsedLogEvent(
        source_type="syslog",
        timestamp=datetime.now(UTC),
        event_name="TRAFFIC",
        source_ip="203.0.113.195",
    )
    threat_matches = await ioc_engine.evaluate_redis(mock_redis, malicious_event)
    assert len(threat_matches) == 1
    assert threat_matches[0].threat_name == "LockBit C2 Server"
    assert threat_matches[0].confidence == 98
    assert threat_matches[0].ioc_type == "ip"


# ---------------------------------------------------------------------------
# 5. ML Isolation Forest Scorer & Risk Formula
# ---------------------------------------------------------------------------
def test_ml_anomaly_and_risk_scorer() -> None:
    """Test Isolation Forest feature extraction, anomaly prediction, and composite formula."""
    detector = UEBAAnomalyDetector()

    # Train on 20 normal feature vectors
    normal_data = [[14.0, 1.0, 0.5, 0.0, 1.0] for _ in range(20)]
    detector.train_baseline(normal_data)

    event = {
        "timestamp": datetime.now(UTC),
        "raw_payload": "ls -la",
        "username": "admin",
        "source_ip": "10.0.0.15",
    }
    feats = detector.extract_features(event)
    assert len(feats) == 5

    score = detector.predict_anomaly_score(feats)
    assert 0.0 <= score <= 1.0

    # Risk scorer with Sigma match + Anomaly score
    sigma_rule = SigmaRule(
        rule_id="r1",
        title="High Severity Rule",
        level="high",
        selection={},
    )
    calc_score = RiskScorer.calculate_risk_score(
        sigma_matches=[sigma_rule],
        ioc_matches=[],
        anomaly_score=0.5,
    )
    # High rule base (60) + anomaly (0.5 * 30 = 15) = 75.0
    assert 70.0 <= calc_score <= 80.0


# ---------------------------------------------------------------------------
# 6. Detection Pipeline & Alert Generation / Redis Stream alerts:new
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_threat_detection_pipeline_and_alert_publishing() -> None:
    """Test multi-layer pipeline detects threat, creates Alert model, and publishes to alerts:new."""
    mock_redis = InMemoryMockRedis()

    rule_yaml = """
title: Critical Ransomware Pattern
id: sigma-ransomware-01
level: critical
tags:
  - attack.impact
detection:
  selection:
    raw_payload|contains: "vssadmin delete shadows"
"""
    sigma_rule = SigmaRule.from_yaml(rule_yaml)
    pipeline = ThreatDetectionPipeline(sigma_engine=SigmaEngine([sigma_rule]))

    malicious_event = {
        "event_name": "PROC_CREATE",
        "source_ip": "192.168.1.50",
        "username": "administrator",
        "raw_payload": "cmd.exe /c vssadmin delete shadows /all /quiet",
        "tenant_id": str(uuid.uuid4()),
    }

    result = await pipeline.analyze_event(
        event=malicious_event,
        redis_client=mock_redis,
        db_session=None,
        tenant_id=malicious_event["tenant_id"],
        publish_alert=True,
    )

    assert result.is_threat is True
    assert result.severity in ("high", "critical")
    assert result.risk_score >= 80.0
    assert len(result.sigma_matches) == 1

    # Verify message was published to Redis Stream alerts:new
    assert "alerts:new" in mock_redis.streams
    published_alerts = mock_redis.streams["alerts:new"]
    assert len(published_alerts) == 1
    alert_payload = published_alerts[0][1]
    assert alert_payload["title"] == "Critical Ransomware Pattern"
    assert alert_payload["source_ip"] == "192.168.1.50"


# ---------------------------------------------------------------------------
# 7. Redis Consumer Group Worker on events:raw
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_event_detection_consumer_worker() -> None:
    """Test consumer group initialization, reading events:raw, processing, and XACK."""
    mock_redis = InMemoryMockRedis()

    # Pre-populate stream events:raw with a message
    event_payload = {
        "payload": json.dumps(
            {
                "event_name": "SuspiciousActivity",
                "source_ip": "10.0.0.200",
                "raw_payload": "mimikatz sekurlsa::logonpasswords",
                "tenant_id": str(uuid.uuid4()),
            }
        )
    }
    await mock_redis.xadd("events:raw", event_payload)

    rule_yaml = """
title: Credential Dumping Mimikatz
id: sigma-cred-001
level: critical
detection:
  selection:
    raw_payload|contains: "mimikatz"
"""
    sigma_rule = SigmaRule.from_yaml(rule_yaml)
    pipeline = ThreatDetectionPipeline(sigma_engine=SigmaEngine([sigma_rule]))

    consumer = EventDetectionConsumer(
        redis_client=mock_redis,
        pipeline=pipeline,
        stream_name="events:raw",
        group_name="detection_workers",
    )

    await consumer.init_consumer_group()
    assert ("events:raw", "detection_workers") in mock_redis.groups

    results = await consumer.process_batch(count=10, block_ms=500)
    assert len(results) == 1
    assert results[0].is_threat is True
    assert results[0].title == "Credential Dumping Mimikatz"

    # Verify message was acknowledged
    assert len(mock_redis.acks) == 1
    ack_stream, ack_group, ack_id = mock_redis.acks[0]
    assert ack_stream == "events:raw"
    assert ack_group == "detection_workers"


# ---------------------------------------------------------------------------
# 8. Detection Rules CRUD & /rules/{id}/test Dry-Run API
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_rules_crud_and_dry_run_api(client: AsyncClient) -> None:
    """Test Detection Rules CRUD endpoints and /rules/{id}/test dry-run endpoint."""
    tenant_id = str(uuid.uuid4())
    headers = {"X-Tenant-ID": tenant_id}

    # 1. Create Sigma Rule
    sigma_create_payload = {
        "title": "Unauthorized SSH Access",
        "description": "Detects unauthorized SSH attempts",
        "rule_type": "sigma",
        "severity": "high",
        "is_active": True,
        "yaml_definition": """
title: Unauthorized SSH Access
id: sigma-ssh-01
level: high
detection:
  selection:
    raw_payload|contains: "Failed password"
""",
        "mitre_attack_tactics": ["attack.credential-access"],
    }
    res_create = await client.post("/api/v1/rules", json=sigma_create_payload, headers=headers)
    assert res_create.status_code == 201
    created_rule = res_create.json()
    rule_id = created_rule["id"]
    assert created_rule["title"] == "Unauthorized SSH Access"
    assert created_rule["rule_type"] == "sigma"

    # 2. List Rules
    res_list = await client.get("/api/v1/rules", headers=headers)
    assert res_list.status_code == 200
    rules_list = res_list.json()
    assert any(r["id"] == rule_id for r in rules_list)

    # 3. Get Rule by ID
    res_get = await client.get(f"/api/v1/rules/{rule_id}", headers=headers)
    assert res_get.status_code == 200
    assert res_get.json()["id"] == rule_id

    # 4. Dry-Run Test Endpoint: POST /rules/{id}/test
    matching_test_payload = {
        "sample_event": {
            "raw_payload": "Failed password for invalid user admin from 10.0.0.1",
            "source_ip": "10.0.0.1",
        }
    }
    res_test_match = await client.post(f"/api/v1/rules/{rule_id}/test", json=matching_test_payload, headers=headers)
    assert res_test_match.status_code == 200
    test_data = res_test_match.json()
    assert test_data["matched"] is True
    assert test_data["rule_id"] == rule_id

    non_matching_payload = {
        "sample_event": {
            "raw_payload": "Accepted publickey for user john",
            "source_ip": "10.0.0.2",
        }
    }
    res_test_nomatch = await client.post(f"/api/v1/rules/{rule_id}/test", json=non_matching_payload, headers=headers)
    assert res_test_nomatch.status_code == 200
    assert res_test_nomatch.json()["matched"] is False

    # 5. Update Rule
    update_payload = {"severity": "critical", "description": "Updated rule description"}
    res_update = await client.put(f"/api/v1/rules/{rule_id}", json=update_payload, headers=headers)
    assert res_update.status_code == 200
    assert res_update.json()["severity"] == "critical"

    # 6. Delete Rule
    res_delete = await client.delete(f"/api/v1/rules/{rule_id}", headers=headers)
    assert res_delete.status_code == 204

    # Verify Deletion
    res_get_deleted = await client.get(f"/api/v1/rules/{rule_id}", headers=headers)
    assert res_get_deleted.status_code == 404
