# network_monitor.py
# week 12 - network traffic monitor

import argparse
import json
import logging
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_PORT_SCAN_THRESHOLD = 25
DEFAULT_SYN_FLOOD_THRESHOLD = 100
DEFAULT_OUTPUT_FILE = "results.json"
DEFAULT_LOG_FILE = "network_monitor.log"
DEFAULT_LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
EXPECTED_FIELD_COUNT = 6
COMMENT_MARKER = "#"
TCP_PROTOCOL = "TCP"
SYN_FLAG = "SYN"


class NetworkConfig:
    """Configuration for network traffic analysis.

    Attributes:
        port_scan_threshold: Number of unique destination ports from a single source IP
            required to declare a port scan.
        syn_flood_threshold: Number of SYN packets from a single source IP required
            to declare a SYN flood.
        output_file: Path to save the final analysis report.
        log_file: Path for the file-based log output.
    """

    def __init__(
        self,
        port_scan_threshold: int = DEFAULT_PORT_SCAN_THRESHOLD,
        syn_flood_threshold: int = DEFAULT_SYN_FLOOD_THRESHOLD,
        output_file: str = DEFAULT_OUTPUT_FILE,
        log_file: str = DEFAULT_LOG_FILE,
    ) -> None:
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.output_file = output_file
        self.log_file = log_file


def setup_logging(verbose: bool, log_file: str) -> logging.Logger:
    """Configure logging with file and console handlers."""
    logger = logging.getLogger("network_monitor")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    formatter = logging.Formatter(DEFAULT_LOG_FORMAT)

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.handlers.clear()
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


def parse_packet_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single traffic log line into a packet dictionary.

    Returns None for empty or comment lines. Raises ValueError for malformed entries.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith(COMMENT_MARKER):
        return None

    parts = [part.strip() for part in stripped.split(",")]
    if len(parts) != EXPECTED_FIELD_COUNT:
        raise ValueError("Packet line does not have exactly %d fields" % EXPECTED_FIELD_COUNT)

    try:
        src_port = int(parts[2])
        dst_port = int(parts[3])
    except ValueError as exc:
        raise ValueError("Port values must be integers") from exc

    return {
        "src_ip": parts[0],
        "dst_ip": parts[1],
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": parts[4],
        "flags": parts[5],
    }


def is_syn_packet(packet: Dict[str, Any]) -> bool:
    """Return True when the packet is a TCP SYN packet."""
    return packet.get("protocol") == TCP_PROTOCOL and SYN_FLAG in packet.get("flags", "")


def load_traffic_log(log_file: str, logger: logging.Logger) -> Tuple[List[Dict[str, Any]], int]:
    """Load and parse the traffic log from disk.

    Returns packets and parse error count.
    """
    packets: List[Dict[str, Any]] = []
    errors = 0

    with open(log_file, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                packet = parse_packet_line(line)
                if packet is not None:
                    packets.append(packet)
            except ValueError:
                logger.error("Failed to parse line %d: %s", line_number, line.strip())
                errors += 1

    return packets, errors


def detect_port_scan(packets: List[Dict[str, Any]], config: NetworkConfig) -> List[Dict[str, Any]]:
    """Detect port scans from traffic packets. Pure function with no side effects."""
    src_ip_ports: Dict[str, set[int]] = defaultdict(set)
    for packet in packets:
        src_ip_ports[packet["src_ip"]].add(packet["dst_port"])

    scan_results: List[Dict[str, Any]] = []
    for src_ip, ports in src_ip_ports.items():
        unique_ports = len(ports)
        if unique_ports > config.port_scan_threshold:
            scan_results.append(
                {
                    "src_ip": src_ip,
                    "unique_ports": unique_ports,
                    "ports": sorted(ports),
                }
            )
    return scan_results


def detect_syn_flood(packets: List[Dict[str, Any]], config: NetworkConfig) -> List[Dict[str, Any]]:
    """Detect SYN floods from traffic packets. Pure function with no side effects."""
    src_ip_syn_count: Dict[str, int] = defaultdict(int)
    for packet in packets:
        if is_syn_packet(packet):
            src_ip_syn_count[packet["src_ip"]] += 1

    flood_results: List[Dict[str, Any]] = []
    for src_ip, syn_count in src_ip_syn_count.items():
        if syn_count > config.syn_flood_threshold:
            flood_results.append({"src_ip": src_ip, "syn_count": syn_count})
    return flood_results


def analyze_traffic(
    packets: List[Dict[str, Any]], config: NetworkConfig
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Analyze packet traffic and return port scan and SYN flood results."""
    scan_results = detect_port_scan(packets, config)
    flood_results = detect_syn_flood(packets, config)
    return scan_results, flood_results


def generate_report(
    total_packets: int,
    parse_errors: int,
    scan_results: List[Dict[str, Any]],
    flood_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Create the JSON-ready results dictionary."""
    return {
        "total_packets": total_packets,
        "parse_errors": parse_errors,
        "port_scans": scan_results,
        "syn_floods": flood_results,
        "summary": "Scanned %d packets. Found %d port scans, %d SYN floods." % (
            total_packets, len(scan_results), len(flood_results)
        ),
    }


def save_report(output_file: str, results: Dict[str, Any], logger: logging.Logger) -> None:
    """Write the result report to a JSON file."""
    with open(output_file, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
    logger.info("Results written to %s", output_file)


def create_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(description="Network traffic monitor")
    parser.add_argument(
        "input_file",
        help="Path to the traffic log file to analyze",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT_FILE,
        help="Output file for JSON report (default: %s)" % DEFAULT_OUTPUT_FILE,
    )
    parser.add_argument(
        "-p",
        "--port-scan-threshold",
        type=int,
        default=DEFAULT_PORT_SCAN_THRESHOLD,
        help="Unique destination ports required to flag a port scan (default: %d)" % DEFAULT_PORT_SCAN_THRESHOLD,
    )
    parser.add_argument(
        "-s",
        "--syn-flood-threshold",
        type=int,
        default=DEFAULT_SYN_FLOOD_THRESHOLD,
        help="SYN packets required to flag a SYN flood (default: %d)" % DEFAULT_SYN_FLOOD_THRESHOLD,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging output",
    )
    return parser


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Validate CLI arguments and exit with a useful message on failure."""
    if not os.path.isfile(args.input_file):
        parser.error("Input file does not exist: %s" % args.input_file)
    if args.port_scan_threshold <= 0:
        parser.error("Port scan threshold must be positive")
    if args.syn_flood_threshold <= 0:
        parser.error("SYN flood threshold must be positive")


def main() -> int:
    parser = create_parser()
    args = parser.parse_args()

    validate_args(args, parser)

    config = NetworkConfig(
        port_scan_threshold=args.port_scan_threshold,
        syn_flood_threshold=args.syn_flood_threshold,
        output_file=args.output,
        log_file=DEFAULT_LOG_FILE,
    )
    logger = setup_logging(args.verbose, config.log_file)

    logger.info("Starting network traffic monitor")
    try:
        packets, parse_errors = load_traffic_log(args.input_file, logger)
    except FileNotFoundError:
        logger.error("Log file not found: %s", args.input_file)
        return 1
    except OSError as exc:
        logger.error("Error reading log file %s: %s", args.input_file, exc)
        return 1

    logger.info("Parsed %d packets with %d parse errors", len(packets), parse_errors)

    scan_results, flood_results = analyze_traffic(packets, config)
    for scan in scan_results:
        logger.warning(
            "PORT SCAN DETECTED from %s (%d ports)", scan["src_ip"], scan["unique_ports"]
        )
    for flood in flood_results:
        logger.warning(
            "SYN FLOOD DETECTED from %s (%d SYN packets)", flood["src_ip"], flood["syn_count"]
        )

    report = generate_report(len(packets), parse_errors, scan_results, flood_results)
    try:
        save_report(config.output_file, report, logger)
    except OSError as exc:
        logger.error("Error writing report to %s: %s", config.output_file, exc)
        return 1

    logger.info("Port scans detected: %d", len(scan_results))
    logger.info("SYN floods detected: %d", len(flood_results))
    logger.info("Done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
