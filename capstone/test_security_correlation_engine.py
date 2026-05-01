import datetime

import pytest

from capstone import security_correlation_engine as engine


def test_log_entry_from_dict_parses_required_fields():
    raw_log = {
        'timestamp': '2023-10-01T10:00:00Z',
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.1',
        'action': 'login_attempt',
        'log_source': 'authentication',
        'bytes_transferred': '2048'
    }

    entry = engine.LogEntry.from_dict(raw_log)

    assert entry.source_ip == '192.168.1.100'
    assert entry.destination_ip == '10.0.0.1'
    assert entry.bytes_transferred == 2048
    assert entry.timestamp == datetime.datetime(2023, 10, 1, 10, 0, 0, tzinfo=datetime.timezone.utc)


def test_correlation_engine_groups_events_and_classifies_attack():
    events = [
        engine.LogEntry.from_dict({
            'timestamp': '2023-10-01T10:00:00Z',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'action': 'login_attempt',
            'status': 'failed',
            'log_source': 'authentication'
        }),
        engine.LogEntry.from_dict({
            'timestamp': '2023-10-01T10:01:00Z',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'action': 'data_exfiltration',
            'log_source': 'firewall'
        })
    ]

    config = engine.validate_config({'time_window_minutes': 5, 'thresholds': {'min_events_per_group': 2}})
    correlation = engine.CorrelationEngine(config)
    groups = correlation.correlate_events(events)

    assert len(groups) == 1
    assert groups[0]['attack_type'] == 'data_exfiltration_after_login'
    assert groups[0]['severity'] == 'high'


def test_validate_threat_indicators_rejects_non_list():
    with pytest.raises(ValueError, match='must be an array of strings'):
        engine.validate_threat_indicators({'ip_blacklist': '203.0.113.10'})


def test_threat_matcher_detects_blacklisted_ip_and_signature():
    threat_data = {
        'ip_blacklist': ['203.0.113.10'],
        'malicious_signatures': ['trojan_dropper'],
        'suspicious_user_agents': []
    }
    matcher = engine.ThreatMatcher(engine.validate_threat_indicators(threat_data))

    entry = engine.LogEntry.from_dict({
        'timestamp': '2023-10-01T10:05:00Z',
        'source_ip': '203.0.113.10',
        'destination_ip': '10.0.0.5',
        'action': 'malware_detection',
        'signature': 'trojan_dropper',
        'log_source': 'ids'
    })

    matches = matcher.scan_logs([entry])

    assert len(matches) == 1
    assert any('Blacklisted IP' in threat for threat in matches[0]['threats'])
    assert any('Malicious signature' in threat for threat in matches[0]['threats'])


def test_validate_config_rejects_invalid_thresholds():
    with pytest.raises(ValueError, match='thresholds.min_events_per_group must be a positive integer'):
        engine.validate_config({'time_window_minutes': 5, 'thresholds': {'min_events_per_group': 0}})


def test_load_log_entries_skips_invalid_log_entries(monkeypatch):
    invalid_log = {
        'timestamp': '2023-10-01T10:00:00Z',
        'source_ip': '192.168.1.100'
    }
    valid_log = {
        'timestamp': '2023-10-01T10:01:00Z',
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.1',
        'action': 'login_attempt',
        'log_source': 'authentication'
    }

    entries = engine.load_log_entries([invalid_log, valid_log])

    assert len(entries) == 1
    assert entries[0].action == 'login_attempt'
