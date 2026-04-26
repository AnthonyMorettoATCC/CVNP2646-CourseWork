import argparse
import json
import logging
import sys
import datetime
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

LOGGER = logging.getLogger(__name__)
DEFAULT_CONFIG = {
    'time_window_minutes': 5,
    'thresholds': {'min_events_per_group': 2}
}


@dataclass
class LogEntry:
    """A data class that standardizes raw JSON logs into a common format."""
    timestamp: datetime.datetime
    source_ip: str
    destination_ip: str
    action: str
    log_source: str
    user: Optional[str] = None
    status: Optional[str] = None
    bytes_transferred: Optional[int] = None
    signature: Optional[str] = None
    severity: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogEntry':
        if 'timestamp' not in data:
            raise KeyError('timestamp')
        timestamp = cls._parse_timestamp(data['timestamp'])
        return cls(
            timestamp=timestamp,
            source_ip=data['source_ip'],
            destination_ip=data['destination_ip'],
            action=data['action'],
            log_source=data['log_source'],
            user=data.get('user'),
            status=data.get('status'),
            bytes_transferred=data.get('bytes_transferred'),
            signature=data.get('signature'),
            severity=data.get('severity'),
            raw_data=data
        )

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime.datetime:
        if isinstance(value, datetime.datetime):
            return value
        if isinstance(value, str):
            normalized = value.replace('Z', '+00:00')
            return datetime.datetime.fromisoformat(normalized)
        raise ValueError('timestamp must be a datetime or ISO-8601 string')

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


class CorrelationEngine:
    """Ingests LogEntry objects and applies correlation rules."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.time_window = datetime.timedelta(minutes=config.get('time_window_minutes', 5))
        self.thresholds = config.get('thresholds', DEFAULT_CONFIG['thresholds'])

    def correlate_events(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        correlated_groups: List[Dict[str, Any]] = []
        sorted_entries = sorted(log_entries, key=lambda x: x.timestamp)
        current_group: List[LogEntry] = []

        for entry in sorted_entries:
            if not current_group:
                current_group = [entry]
                continue

            last_entry = current_group[-1]
            same_source = entry.source_ip == current_group[0].source_ip
            within_window = entry.timestamp - last_entry.timestamp <= self.time_window

            if same_source and within_window:
                current_group.append(entry)
            else:
                self._flush_group(current_group, correlated_groups)
                current_group = [entry]

        self._flush_group(current_group, correlated_groups)
        return correlated_groups

    def _flush_group(self, group: List[LogEntry], output: List[Dict[str, Any]]) -> None:
        if not group:
            return
        min_events = self.thresholds.get('min_events_per_group', 2)
        if len(group) < min_events:
            return
        output.append({
            'correlation_id': f"corr_{len(output) + 1:03d}",
            'events': [entry.to_dict() for entry in group],
            'attack_type': self._classify_attack(group),
            'severity': self._calculate_severity(group)
        })

    def _classify_attack(self, events: List[LogEntry]) -> str:
        actions = [e.action for e in events]
        if 'login_attempt' in actions and 'data_exfiltration' in actions:
            return 'data_exfiltration_after_login'
        if all(action == 'login_attempt' for action in actions):
            failed_count = sum(1 for e in events if e.status == 'failed')
            if failed_count >= len(events) - 1:
                return 'brute_force_login'
            return 'suspicious_login_sequence'
        if 'malware_detection' in actions:
            return 'malware_infection'
        return 'unknown'

    def _calculate_severity(self, events: List[LogEntry]) -> str:
        high_severity_actions = {'malware_detection', 'data_exfiltration'}
        if any(event.action in high_severity_actions for event in events):
            return 'high'
        if len(events) > 5:
            return 'medium'
        return 'low'


class ThreatMatcher:
    """Scans log data for matches against threat indicators."""

    def __init__(self, threat_indicators: Dict[str, Any]):
        self.ip_blacklist = set(threat_indicators.get('ip_blacklist', []))
        self.malicious_signatures = set(threat_indicators.get('malicious_signatures', []))
        self.suspicious_user_agents = set(threat_indicators.get('suspicious_user_agents', []))

    def scan_logs(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        for entry in log_entries:
            threats = self._check_entry(entry)
            if threats:
                matches.append({'log_entry': entry.to_dict(), 'threats': threats})
        return matches

    def _check_entry(self, entry: LogEntry) -> List[str]:
        threats: List[str] = []
        if entry.source_ip in self.ip_blacklist:
            threats.append(f"Blacklisted IP: {entry.source_ip}")
        if entry.signature and entry.signature in self.malicious_signatures:
            threats.append(f"Malicious signature: {entry.signature}")
        if entry.raw_data and entry.raw_data.get('user_agent') in self.suspicious_user_agents:
            threats.append(f"Suspicious user agent: {entry.raw_data['user_agent']}")
        return threats


class AttackChainBuilder:
    """Builds sequential attack chains from correlated event groups."""

    def build_chains(self, correlated_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        chains: List[Dict[str, Any]] = []
        for corr_event in correlated_events:
            chains.append({
                'chain_id': f"chain_{len(chains) + 1:03d}",
                'attack_type': corr_event.get('attack_type', 'unknown'),
                'severity': corr_event.get('severity', 'low'),
                'timeline': self._create_timeline(corr_event['events']),
                'description': self._generate_description(corr_event)
            })
        return chains

    def _create_timeline(self, events: List[Dict[str, Any]]) -> List[str]:
        return [f"{event['timestamp']}: {event['action']}" for event in events]

    def _generate_description(self, corr_event: Dict[str, Any]) -> str:
        attack_type = corr_event.get('attack_type', 'unknown')
        event_count = len(corr_event.get('events', []))
        descriptions = {
            'brute_force_login': f"Brute force attack with {event_count} login attempts",
            'data_exfiltration_after_login': f"Data exfiltration following authentication ({event_count} events)",
            'malware_infection': f"Malware infection detected ({event_count} related events)",
            'suspicious_login_sequence': f"Suspicious login sequence ({event_count} events)",
            'unknown': f"Unclassified attack pattern ({event_count} events)"
        }
        return descriptions.get(attack_type, descriptions['unknown'])


class ReportGenerator:
    """Exports correlated events, attack chains, and alerts to JSON."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _write_json(self, filename: str, data: Any) -> None:
        output_path = self.output_dir / filename
        with output_path.open('w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def generate_correlated_events_report(self, correlated_events: List[Dict[str, Any]]) -> None:
        self._write_json('correlated_events.json', correlated_events)

    def generate_attack_chains_report(self, attack_chains: List[Dict[str, Any]]) -> None:
        self._write_json('attack_chains.json', attack_chains)

    def generate_alert_report(self, correlated_events: List[Dict[str, Any]], threat_matches: List[Dict[str, Any]]) -> None:
        alerts: List[Dict[str, Any]] = []
        for event in correlated_events:
            if event.get('severity') == 'high':
                alerts.append({
                    'alert_id': f"alert_{len(alerts) + 1:03d}",
                    'type': 'correlated_attack',
                    'severity': 'high',
                    'description': f"High-severity {event.get('attack_type')} detected",
                    'details': event
                })
        for match in threat_matches:
            alerts.append({
                'alert_id': f"alert_{len(alerts) + 1:03d}",
                'type': 'threat_indicator_match',
                'severity': 'high',
                'description': f"Threat indicators detected: {', '.join(match.get('threats', []))}",
                'details': match
            })
        self._write_json('alert_report.json', alerts)


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        stream=sys.stdout
    )


def load_json_file(file_path: Path) -> Any:
    try:
        with file_path.open('r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        LOGGER.error('File not found: %s', file_path)
        raise
    except json.JSONDecodeError as exc:
        LOGGER.error('Invalid JSON in %s: %s', file_path, exc)
        raise


def load_log_entries(logs_data: List[Dict[str, Any]]) -> List[LogEntry]:
    log_entries: List[LogEntry] = []
    for log_data in logs_data:
        try:
            log_entries.append(LogEntry.from_dict(log_data))
        except (KeyError, ValueError) as exc:
            LOGGER.warning('Skipping invalid log entry: %s', exc)
    LOGGER.info('Loaded %d valid log entries', len(log_entries))
    return log_entries


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Security Log Correlation Engine - Analyze logs from multiple sources to correlate events and detect multi-stage attacks.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python security_correlation_engine.py --logs input_sample.json --config config.json --intel threat_indicators.json
  python security_correlation_engine.py -l input_sample.json -c config.json -i threat_indicators.json -o ./results -v
'''
    )
    parser.add_argument('--logs', '-l', required=True, type=Path, help='Path to the logs.json file containing the raw security events')
    parser.add_argument('--config', '-c', required=True, type=Path, help='Path to config.json defining the correlation logic')
    parser.add_argument('--intel', '-i', required=True, type=Path, help='Path to threat_indicators.json for matching against known IOCs')
    parser.add_argument('--output', '-o', type=Path, default=Path('./output'), help='Directory where report JSON files are saved')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable debug logging')
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    LOGGER.info('Starting Security Log Correlation Engine')

    for path in (args.logs, args.config, args.intel):
        if not path.exists():
            LOGGER.error('Required file does not exist: %s', path)
            return 1

    try:
        logs_data = load_json_file(args.logs)
        config_data = load_json_file(args.config)
        threat_data = load_json_file(args.intel)
    except Exception:
        return 1

    if not isinstance(logs_data, list):
        LOGGER.error('Log input must be a JSON array of log entries')
        return 1

    log_entries = load_log_entries(logs_data)
    if not log_entries:
        LOGGER.error('No valid log entries to process')
        return 1

    correlation_engine = CorrelationEngine(config_data)
    threat_matcher = ThreatMatcher(threat_data)
    attack_chain_builder = AttackChainBuilder()
    report_generator = ReportGenerator(args.output)

    correlated_events = correlation_engine.correlate_events(log_entries)
    threat_matches = threat_matcher.scan_logs(log_entries)
    attack_chains = attack_chain_builder.build_chains(correlated_events)

    report_generator.generate_correlated_events_report(correlated_events)
    report_generator.generate_attack_chains_report(attack_chains)
    report_generator.generate_alert_report(correlated_events, threat_matches)

    LOGGER.info('Processing complete')
    LOGGER.info('Correlated event groups: %d', len(correlated_events))
    LOGGER.info('Threat matches: %d', len(threat_matches))
    LOGGER.info('Attack chains: %d', len(attack_chains))
    LOGGER.info('Reports saved to: %s', args.output.resolve())
    return 0


if __name__ == '__main__':
    sys.exit(main())
