"""Tests for 3-Layer Threat Detection Engine (Sigma, IOC, ML Isolation Forest)."""

from datetime import UTC, datetime

from sentinel_common.detection.ioc_engine import IOCEngine
from sentinel_common.detection.ml_engine import RiskScorer, UEBAAnomalyDetector
from sentinel_common.detection.parsers import LogParser, ParsedLogEvent
from sentinel_common.detection.sigma_engine import SigmaEngine, SigmaRule


def test_log_parsers() -> None:
    """Test Syslog, CloudTrail, and VPC Flow Log parsing."""
    # 1. Syslog Parser
    syslog_msg = (
        "<134>1 2026-10-07T00:00:00Z web01 sshd 1234 - - Failed password for invalid user"
        " admin from 192.168.1.100 port 54321 ssh2"
    )
    parsed_syslog = LogParser.parse_syslog(syslog_msg)
    assert parsed_syslog.source_type == "syslog"
    assert parsed_syslog.source_ip == "192.168.1.100"
    assert parsed_syslog.username == "admin"

    # 2. CloudTrail Parser
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

    # 3. VPC Flow Parser
    vpc_line = "2 123456789012 eni-01235678 192.168.1.5 10.0.0.1 443 49152 6 10 8400 1600000000 1600000060 REJECT OK"
    parsed_vpc = LogParser.parse_vpc_flow(vpc_line)
    assert parsed_vpc.source_ip == "192.168.1.5"
    assert parsed_vpc.destination_ip == "10.0.0.1"
    assert "REJECT" in parsed_vpc.event_name


def test_layer1_sigma_engine() -> None:
    """Test Layer 1 Sigma rule matching."""
    rule_yaml = """
title: Detect Suspicious PowerShell Execution
id: sigma-cmd-002
level: high
description: Detects encoded powershell command execution
detection:
  selection:
    raw_payload|contains:
      - "powershell -enc"
"""
    rule = SigmaRule.from_yaml(rule_yaml)
    engine = SigmaEngine([rule])

    # Test Non-matching log
    clean_event = ParsedLogEvent(
        source_type="syslog",
        timestamp=datetime.now(UTC),
        event_name="CMD_EXEC",
        raw_payload="dir C:\\Users",
    )
    assert len(engine.evaluate(clean_event)) == 0

    # Test Matching log
    malicious_event = ParsedLogEvent(
        source_type="syslog",
        timestamp=datetime.now(UTC),
        event_name="CMD_EXEC",
        raw_payload="C:\\Windows\\System32\\powershell -enc SQBFAFgA...",
    )
    matches = engine.evaluate(malicious_event)
    assert len(matches) == 1
    assert matches[0].title == "Detect Suspicious PowerShell Execution"
    assert matches[0].level == "high"


def test_layer2_ioc_engine() -> None:
    """Test Layer 2 IOC Threat Intel matching."""
    ioc_engine = IOCEngine()
    ioc_engine.load_ioc("ip", "198.51.100.44", "Known Cobalt Strike C2", confidence=95)

    clean_event = ParsedLogEvent(
        source_type="syslog",
        timestamp=datetime.now(UTC),
        event_name="TRAFFIC",
        source_ip="8.8.8.8",
    )
    assert len(ioc_engine.evaluate(clean_event)) == 0

    malicious_event = ParsedLogEvent(
        source_type="syslog",
        timestamp=datetime.now(UTC),
        event_name="TRAFFIC",
        source_ip="198.51.100.44",
    )
    ioc_matches = ioc_engine.evaluate(malicious_event)
    assert len(ioc_matches) == 1
    assert ioc_matches[0].threat_name == "Known Cobalt Strike C2"
    assert ioc_matches[0].confidence == 95


def test_layer3_ml_ueba_and_risk_scorer() -> None:
    """Test Layer 3 Isolation Forest UEBA anomaly score and composite 0-100 risk calculation."""
    detector = UEBAAnomalyDetector()

    # Create normal baseline feature vectors (hour, sigma_flag, ioc_flag)
    normal_features = [[12.0, 0.0, 0.0] for _ in range(20)]
    detector.train_baseline(normal_features)

    # Normal activity score
    normal_score = detector.predict_anomaly_score([12.0, 0.0, 0.0])
    assert 0.0 <= normal_score <= 0.5

    # Anomalous activity score
    anomalous_score = detector.predict_anomaly_score([3.0, 1.0, 1.0])
    assert anomalous_score >= normal_score

    # Test RiskScorer composite calculation
    rule_yaml = (
        "title: High Severity Threat\nid: s1\nlevel: high\ndetection:\n  selection:\n"
        "    raw_payload|contains:\n      - test"
    )
    sigma_match = SigmaRule.from_yaml(rule_yaml)

    risk_score = RiskScorer.calculate_risk_score(
        sigma_matches=[sigma_match],
        ioc_matches=[],
        anomaly_score=0.8,
    )
    # High rule baseline (60.0) + Anomaly (0.8 * 30.0 = 24.0) = 84.0
    assert 80.0 <= risk_score <= 100.0
