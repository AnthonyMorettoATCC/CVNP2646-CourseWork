import json
import logging
import os
import argparse
import pytest

from week12 import network_monitor


@pytest.fixture
def valid_packet_line() -> str:
    return "192.168.1.10,10.0.0.1,52100,80,TCP,SYN"


@pytest.fixture
def sample_packets() -> list[dict]:
    return [
        {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 50000, "dst_port": 80, "protocol": "TCP", "flags": "SYN"},
        {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 50001, "dst_port": 443, "protocol": "TCP", "flags": "ACK"},
        {"src_ip": "3.3.3.3", "dst_ip": "2.2.2.2", "src_port": 50002, "dst_port": 22, "protocol": "TCP", "flags": "SYN"},
    ]


def test_parse_packet_line_returns_packet_dict(valid_packet_line):
    packet = network_monitor.parse_packet_line(valid_packet_line)

    assert packet is not None
    assert packet["src_ip"] == "192.168.1.10"
    assert packet["dst_port"] == 80
    assert packet["protocol"] == "TCP"
    assert packet["flags"] == "SYN"


def test_parse_packet_line_ignores_blank_line():
    assert network_monitor.parse_packet_line("   \n") is None


def test_parse_packet_line_ignores_comment_line():
    assert network_monitor.parse_packet_line("# comment") is None


def test_parse_packet_line_raises_on_missing_fields():
    with pytest.raises(ValueError, match="exactly 6 fields"):
        network_monitor.parse_packet_line("192.168.1.10,10.0.0.1,80,TCP")


def test_parse_packet_line_raises_on_non_integer_ports():
    with pytest.raises(ValueError, match="Port values must be integers"):
        network_monitor.parse_packet_line("192.168.1.10,10.0.0.1,not-a-port,80,TCP,SYN")


def test_parse_packet_line_raises_on_extra_fields():
    with pytest.raises(ValueError, match="exactly 6 fields"):
        network_monitor.parse_packet_line("1.1.1.1,2.2.2.2,1000,2000,TCP,SYN,EXTRA")


def test_is_syn_packet_returns_true_for_syn():
    packet = {"protocol": "TCP", "flags": "SYN"}
    assert network_monitor.is_syn_packet(packet)


def test_is_syn_packet_returns_false_for_non_tcp():
    packet = {"protocol": "UDP", "flags": "SYN"}
    assert not network_monitor.is_syn_packet(packet)


def test_is_syn_packet_returns_false_when_no_syn_flag():
    packet = {"protocol": "TCP", "flags": "ACK"}
    assert not network_monitor.is_syn_packet(packet)


def test_detect_port_scan_flags_scan_when_threshold_exceeded():
    packets = [
        {"src_ip": "1.1.1.1", "dst_port": port} for port in range(1, 28)
    ]
    config = network_monitor.NetworkConfig(port_scan_threshold=25)

    scan_results = network_monitor.detect_port_scan(packets, config)

    assert len(scan_results) == 1
    assert scan_results[0]["src_ip"] == "1.1.1.1"
    assert scan_results[0]["unique_ports"] == 27


def test_detect_port_scan_ignores_below_threshold():
    packets = [
        {"src_ip": "1.1.1.1", "dst_port": port} for port in range(1, 25)
    ]
    config = network_monitor.NetworkConfig(port_scan_threshold=25)

    scan_results = network_monitor.detect_port_scan(packets, config)

    assert scan_results == []


def test_detect_port_scan_supports_multiple_sources():
    packets = [
        {"src_ip": "1.1.1.1", "dst_port": 80},
        {"src_ip": "1.1.1.1", "dst_port": 81},
        {"src_ip": "2.2.2.2", "dst_port": 80},
    ]
    config = network_monitor.NetworkConfig(port_scan_threshold=1)

    scan_results = network_monitor.detect_port_scan(packets, config)

    assert len(scan_results) == 1
    assert scan_results[0]["src_ip"] == "1.1.1.1"


def test_detect_syn_flood_detects_when_threshold_exceeded():
    packets = [
        {"src_ip": "4.4.4.4", "protocol": "TCP", "flags": "SYN"} for _ in range(6)
    ]
    config = network_monitor.NetworkConfig(syn_flood_threshold=5)

    flood_results = network_monitor.detect_syn_flood(packets, config)

    assert len(flood_results) == 1
    assert flood_results[0]["src_ip"] == "4.4.4.4"
    assert flood_results[0]["syn_count"] == 6


def test_detect_syn_flood_ignores_non_syn_packets():
    packets = [
        {"src_ip": "4.4.4.4", "protocol": "TCP", "flags": "ACK"} for _ in range(10)
    ]
    config = network_monitor.NetworkConfig(syn_flood_threshold=5)

    assert network_monitor.detect_syn_flood(packets, config) == []


def test_detect_syn_flood_ignores_udp_packets():
    packets = [
        {"src_ip": "4.4.4.4", "protocol": "UDP", "flags": "SYN"} for _ in range(10)
    ]
    config = network_monitor.NetworkConfig(syn_flood_threshold=5)

    assert network_monitor.detect_syn_flood(packets, config) == []


def test_analyze_traffic_returns_both_types(sample_packets):
    config = network_monitor.NetworkConfig(port_scan_threshold=1, syn_flood_threshold=0)

    scan_results, flood_results = network_monitor.analyze_traffic(sample_packets, config)

    assert any(scan["src_ip"] == "1.1.1.1" for scan in scan_results)
    assert any(flood["src_ip"] == "1.1.1.1" for flood in flood_results)


def test_load_traffic_log_counts_invalid_lines(tmp_path):
    log_path = tmp_path / "test.log"
    log_path.write_text("# comment\n1.1.1.1,2.2.2.2,1000,2000,TCP,SYN\ninvalid,line\n")
    logger = network_monitor.setup_logging(False, str(tmp_path / "monitor.log"))

    packets, errors = network_monitor.load_traffic_log(str(log_path), logger)

    assert len(packets) == 1
    assert errors == 1


def test_save_report_writes_file(tmp_path):
    output_path = tmp_path / "report.json"
    report = {"total_packets": 1, "parse_errors": 0, "port_scans": [], "syn_floods": []}
    logger = network_monitor.setup_logging(False, str(tmp_path / "monitor.log"))

    network_monitor.save_report(str(output_path), report, logger)

    assert os.path.exists(output_path)
    with open(output_path, "r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    assert loaded["total_packets"] == 1


def test_validate_args_rejects_missing_file():
    parser = network_monitor.create_parser()
    args = parser.parse_args(["missing.log"])

    with pytest.raises(SystemExit):
        network_monitor.validate_args(args, parser)


def test_validate_args_rejects_nonpositive_port_scan_threshold(tmp_path):
    parser = network_monitor.create_parser()
    sample_log = tmp_path / "traffic_sample.log"
    sample_log.write_text("1.1.1.1,2.2.2.2,1000,2000,TCP,SYN\n")
    args = parser.parse_args([str(sample_log), "-p", "0"])

    with pytest.raises(SystemExit):
        network_monitor.validate_args(args, parser)


def test_validate_args_rejects_nonpositive_syn_flood_threshold(tmp_path):
    parser = network_monitor.create_parser()
    sample_log = tmp_path / "traffic_sample.log"
    sample_log.write_text("1.1.1.1,2.2.2.2,1000,2000,TCP,SYN\n")
    args = parser.parse_args([str(sample_log), "-s", "-1"])

    with pytest.raises(SystemExit):
        network_monitor.validate_args(args, parser)


def test_load_traffic_log_logs_parse_error(tmp_path):
    log_path = tmp_path / "test.log"
    log_path.write_text("1.1.1.1,2.2.2.2,abc,80,TCP,SYN\n")
    log_file = tmp_path / "monitor.log"
    logger = network_monitor.setup_logging(False, str(log_file))

    packets, errors = network_monitor.load_traffic_log(str(log_path), logger)

    assert len(packets) == 0
    assert errors == 1

    with open(log_file, "r", encoding="utf-8") as handle:
        contents = handle.read()
    assert "Failed to parse line 1" in contents


def test_create_parser_includes_expected_flags():
    parser = network_monitor.create_parser()

    assert parser.get_default("output") == "results.json"
    assert parser.get_default("port_scan_threshold") == 25
    assert parser.get_default("syn_flood_threshold") == 100
