import json
from datetime import datetime
from collections import Counter


def normalize_indicator(raw):
    """Normalize different vendor indicator formats into a common schema.

    Standard output keys:
    - type
    - value
    - confidence (int or None)
    - threat_level (string or None)
    - sources (list)

    The function is resilient to missing fields and uses fallbacks:
    - VendorA: type, value, confidence, threat
    - VendorB: indicator_type, indicator_value, score, severity
    - VendorC: category, ioc, reliability, risk
    """

    if not isinstance(raw, dict):
        raise ValueError("Indicator input must be a dict")

    t = raw.get("type") or raw.get("indicator_type") or raw.get("category")
    v = raw.get("value") or raw.get("indicator_value") or raw.get("ioc")

    confidence = raw.get("confidence")
    if confidence is None:
        confidence = raw.get("score")
    if confidence is None:
        confidence = raw.get("reliability")

    threat_level = raw.get("threat")
    if threat_level is None:
        threat_level = raw.get("severity")
    if threat_level is None:
        threat_level = raw.get("risk")

    # Normalize numeric-like values to int when possible, else keep as is
    if confidence is not None:
        try:
            confidence = int(confidence)
        except (ValueError, TypeError):
            pass

    # Ensure sources exists as a list
    sources = raw.get("sources")
    if sources is None:
        sources = []
    elif isinstance(sources, str):
        sources = [sources]
    elif not isinstance(sources, list):
        sources = list(sources)

    normalized = {
        "type": t if t is not None else "unknown",
        "value": v if v is not None else "",
        "confidence": confidence,
        "threat_level": threat_level,
        "sources": sources,
    }

    return normalized


def validate_indicators(indicators):
    """Validate indicators for data quality issues.

    Checks:
    - Required fields: id, type, value, confidence
    - Confidence: 0-100 range
    - Type: valid values ("ip", "domain", "hash", "url")
    - Value: non-empty string

    Returns:
    - valid: list of valid indicators
    - error_count: number of errors found
    - errors: list of error messages
    """
    valid = []
    errors = []
    valid_types = {"ip", "domain", "hash", "url"}

    for idx, indicator in enumerate(indicators):
        # Check required fields
        required_fields = ["id", "type", "value", "confidence"]
        missing_fields = [field for field in required_fields if field not in indicator]
        if missing_fields:
            errors.append(f"Indicator {idx}: missing required fields {missing_fields}")
            continue

        # Check confidence range
        confidence = indicator["confidence"]
        if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 100):
            errors.append(f"Indicator {idx}: confidence {confidence} out of range (0-100)")
            continue

        # Check type validity
        indicator_type = indicator["type"]
        if indicator_type not in valid_types:
            errors.append(f"Indicator {idx}: invalid type '{indicator_type}' (must be one of {valid_types})")
            continue

        # Check value is non-empty string
        value = indicator["value"]
        if not isinstance(value, str) or not value.strip():
            errors.append(f"Indicator {idx}: value must be non-empty string")
            continue

        # All checks passed
        valid.append(indicator)

    return valid, len(errors), errors


def deduplicate_indicators(indicators):
    """Deduplicate indicators based on (type, value) pairs.

    Logic:
    - Uses (type, value) tuple as dictionary key
    - When duplicate found, keeps the one with higher confidence
    - Merges sources lists from both indicators (removes duplicates)
    - Returns: (unique_indicators_list, duplicate_count)

    Confidence comparison:
    - If new confidence > existing confidence: replace with new indicator
    - If new confidence <= existing confidence: keep existing, merge sources
    - None confidence values are treated as 0 for comparison

    Sources merging:
    - Combine both sources lists
    - Remove duplicates while preserving order
    - Handle None sources as empty lists
    """
    unique_indicators = {}
    duplicate_count = 0

    for indicator in indicators:
        # Create the key as (type, value) tuple
        key = (indicator["type"], indicator["value"])

        # Get confidence values, treating None as 0
        current_confidence = indicator.get("confidence") or 0
        existing_confidence = 0

        if key in unique_indicators:
            existing_confidence = unique_indicators[key].get("confidence") or 0
            duplicate_count += 1

        # Compare confidence values
        if key not in unique_indicators or current_confidence > existing_confidence:
            # Either new indicator or higher confidence - use current indicator
            unique_indicators[key] = indicator.copy()
        else:
            # Keep existing indicator, but merge sources
            existing_indicator = unique_indicators[key]

            # Merge sources lists
            existing_sources = existing_indicator.get("sources") or []
            current_sources = indicator.get("sources") or []

            # Combine and deduplicate while preserving order
            merged_sources = []
            seen = set()
            for source in existing_sources + current_sources:
                if source not in seen:
                    seen.add(source)
                    merged_sources.append(source)

            existing_indicator["sources"] = merged_sources

    # Convert back to list
    unique_list = list(unique_indicators.values())

    return unique_list, duplicate_count


def filter_indicators(indicators, min_conf=85, levels=None, types=None):
    """Apply configurable filters to indicators.

    Filters:
    - confidence >= min_conf (default: 85)
    - threat_level in levels (default: ["high", "critical"])
    - type in types (default: ["ip", "domain"])

    Returns filtered list of indicators that match all criteria.
    """
    if levels is None:
        levels = ["high", "critical"]
    if types is None:
        types = ["ip", "domain"]

    return [
        ind for ind in indicators
        if ind["confidence"] >= min_conf
        and ind["threat_level"] in levels
        and ind["type"] in types
    ]


def transform_to_firewall(indicators):
    """Transform indicators to firewall blocklist format."""
    entries = []
    for ind in indicators:
        entry = {
            "address": ind["value"],
            "action": "block",
            "priority": "high" if ind["threat_level"] == "critical" else "medium",
            "reason": f"Threat level: {ind['threat_level']}, Confidence: {ind['confidence']}%",
            "sources": ind["sources"]
        }
        entries.append(entry)

    return {
        "generated_at": datetime.now().isoformat(),
        "total_entries": len(entries),
        "blocklist": entries
    }


def transform_to_siem(indicators):
    """Transform indicators to SIEM feed format with different field names."""
    events = []
    for ind in indicators:
        event = {
            "event_type": "threat_intelligence",
            "indicator_type": ind["type"],
            "indicator_value": ind["value"],
            "severity_score": ind["confidence"],
            "threat_category": ind["threat_level"],
            "detection_sources": ind["sources"],
            "timestamp": datetime.now().isoformat(),
            "status": "active"
        }
        events.append(event)

    return {
        "feed_name": "aggregated_threat_intelligence",
        "feed_version": "1.0",
        "last_updated": datetime.now().isoformat(),
        "event_count": len(events),
        "events": events
    }


def transform_to_text_report(indicators):
    """Transform indicators to formatted text report."""
    report_lines = []
    report_lines.append("=" * 60)
    report_lines.append("THREAT INTELLIGENCE SUMMARY REPORT")
    report_lines.append("=" * 60)
    report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"Total Indicators: {len(indicators)}")
    report_lines.append("")

    # Group by type
    types = {}
    for ind in indicators:
        t = ind["type"]
        if t not in types:
            types[t] = []
        types[t].append(ind)

    for type_name, type_indicators in types.items():
        report_lines.append(f"{type_name.upper()} INDICATORS ({len(type_indicators)})")
        report_lines.append("-" * 40)

        for ind in sorted(type_indicators, key=lambda x: x["confidence"], reverse=True):
            report_lines.append(f"Value: {ind['value']}")
            report_lines.append(f"Confidence: {ind['confidence']}%")
            report_lines.append(f"Threat Level: {ind['threat_level']}")
            report_lines.append(f"Sources: {', '.join(ind['sources']) if ind['sources'] else 'None'}")
            report_lines.append("")

    report_lines.append("=" * 60)
    return "\n".join(report_lines)


def analyze_indicators_with_counter(indicators):
    """Analyze threat indicators using collections.Counter.

    Returns three Counter objects:
    - type_counts: distribution by indicator type
    - threat_counts: distribution by threat level
    - source_counts: unique indicators contributed by each source
    """

    # 1. Count distribution by type
    type_counts = Counter(ind["type"] for ind in indicators)

    # 2. Count distribution by threat_level
    threat_counts = Counter(ind["threat_level"] for ind in indicators)

    # 3. Count unique indicators each source contributed
    # Since sources is a list, we need to flatten and count unique indicators per source
    source_indicator_map = {}

    for ind in indicators:
        # Create a unique key for this indicator (type + value)
        indicator_key = (ind["type"], ind.get("value", ""))

        # For each source that contributed this indicator, increment their count
        for source in ind.get("sources", []):
            if source not in source_indicator_map:
                source_indicator_map[source] = set()
            source_indicator_map[source].add(indicator_key)

    # Convert to Counter: each source gets count of unique indicators they contributed
    source_counts = Counter({source: len(indicators_set)
                           for source, indicators_set in source_indicator_map.items()})

    return type_counts, threat_counts, source_counts


if __name__ == "__main__":
    # Test normalization
    samples = [
        {"type": "ip", "value": "203.0.113.10", "confidence": 95, "threat": "critical", "sources": "vendor_a"},
        {"indicator_type": "ip", "indicator_value": "203.0.113.10", "score": 80, "severity": "high", "sources": ["vendor_b"]},
        {"category": "domain", "ioc": "malicious-example.com", "reliability": 94, "risk": "critical"},
        {"indicator_type": "url", "indicator_value": "http://203.0.113.77/malware.exe", "score": 78, "severity": "medium"},
        {}  # missing fields
    ]

    print("=== Normalization Tests ===")
    for i, raw in enumerate(samples, 1):
        print(f"normalized {i}:", normalize_indicator(raw))

    # Test validation
    test_indicators = [
        {"id": "test-1", "type": "ip", "value": "203.0.113.10", "confidence": 95},  # valid
        {"id": "test-2", "type": "domain", "value": "malicious-example.com", "confidence": 85},  # valid
        {"id": "test-3", "type": "hash", "value": "5f4dcc3b5aa765d61d8327deb882cf99", "confidence": 90},  # valid
        {"id": "test-4", "type": "url", "value": "http://203.0.113.77/malware.exe", "confidence": 78},  # valid
        {"id": "test-5", "type": "ip", "value": "", "confidence": 75},  # empty value
        {"id": "test-6", "type": "invalid", "value": "203.0.113.11", "confidence": 80},  # invalid type
        {"id": "test-7", "type": "ip", "value": "203.0.113.12", "confidence": 150},  # confidence too high
        {"id": "test-8", "type": "ip", "value": "203.0.113.13", "confidence": -5},  # confidence too low
        {"type": "ip", "value": "203.0.113.14", "confidence": 70},  # missing id
        {"id": "test-9", "value": "203.0.113.15", "confidence": 80},  # missing type
        {"id": "test-10", "type": "ip", "confidence": 85},  # missing value
        {"id": "test-11", "type": "ip", "value": "203.0.113.16"},  # missing confidence
    ]

    print("\n=== Validation Tests ===")
    valid, error_count, errors = validate_indicators(test_indicators)
    print(f"Valid indicators: {len(valid)}")
    print(f"Errors found: {error_count}")
    if errors:
        print("Error details:")
        for error in errors:
            print(f"  - {error}")
    print(f"Valid indicators: {[ind['id'] for ind in valid]}")

    # Test deduplication
    dedup_test_indicators = [
        {"id": "a-1", "type": "ip", "value": "203.0.113.10", "confidence": 95, "sources": ["vendor_a"]},
        {"id": "b-1", "type": "ip", "value": "203.0.113.10", "confidence": 80, "sources": ["vendor_b"]},  # lower confidence, should merge sources
        {"id": "c-1", "type": "ip", "value": "203.0.113.10", "confidence": 98, "sources": ["vendor_c"]},  # higher confidence, should replace
        {"id": "a-2", "type": "domain", "value": "malicious-example.com", "confidence": 92, "sources": ["vendor_a"]},
        {"id": "c-2", "type": "domain", "value": "malicious-example.com", "confidence": 94, "sources": ["vendor_c"]},  # higher confidence, should replace
        {"id": "b-2", "type": "domain", "value": "malicious-example.com", "confidence": 90, "sources": ["vendor_b"]},  # lower confidence, should merge
        {"id": "a-3", "type": "hash", "value": "5f4dcc3b5aa765d61d8327deb882cf99", "confidence": 88, "sources": ["vendor_a"]},
        {"id": "b-3", "type": "hash", "value": "5f4dcc3b5aa765d61d8327deb882cf99", "confidence": 88, "sources": ["vendor_b"]},  # equal confidence, should merge
        {"id": "a-4", "type": "url", "value": "http://203.0.113.77/malware.exe", "confidence": 73, "sources": ["vendor_a"]},
        {"id": "b-4", "type": "url", "value": "http://203.0.113.77/malware.exe", "confidence": None, "sources": ["vendor_b"]},  # None confidence (0), should merge
        {"id": "unique-1", "type": "ip", "value": "192.168.1.1", "confidence": 85, "sources": ["vendor_a"]},  # unique
    ]

    print("\n=== Deduplication Tests ===")
    unique, dup_count = deduplicate_indicators(dedup_test_indicators)
    print(f"Original indicators: {len(dedup_test_indicators)}")
    print(f"Unique indicators: {len(unique)}")
    print(f"Duplicates removed: {dup_count}")

    print("\nFinal unique indicators:")
    for ind in sorted(unique, key=lambda x: x["id"]):
        print(f"  {ind['id']}: {ind['type']}:{ind['value']} (conf:{ind['confidence']}) sources:{ind['sources']}")

    # Test filtering
    filter_test_indicators = [
        {"id": "f-1", "type": "ip", "value": "203.0.113.10", "confidence": 95, "threat_level": "critical", "sources": ["vendor_a"]},
        {"id": "f-2", "type": "ip", "value": "198.51.100.45", "confidence": 85, "threat_level": "high", "sources": ["vendor_b"]},
        {"id": "f-3", "type": "domain", "value": "malicious-example.com", "confidence": 94, "threat_level": "critical", "sources": ["vendor_c"]},
        {"id": "f-4", "type": "domain", "value": "badcdn-example.net", "confidence": 77, "threat_level": "medium", "sources": ["vendor_a"]},  # low confidence
        {"id": "f-5", "type": "hash", "value": "5f4dcc3b5aa765d61d8327deb882cf99", "confidence": 88, "threat_level": "high", "sources": ["vendor_b"]},  # hash type
        {"id": "f-6", "type": "url", "value": "http://203.0.113.77/malware.exe", "confidence": 73, "threat_level": "critical", "sources": ["vendor_c"]},  # low confidence
        {"id": "f-7", "type": "ip", "value": "192.168.1.100", "confidence": 90, "threat_level": "low", "sources": ["vendor_a"]},  # wrong threat level
    ]

    print("\n=== Filtering Tests ===")
    print(f"Original indicators: {len(filter_test_indicators)}")

    # Default filters: conf >= 85, levels=["high", "critical"], types=["ip", "domain"]
    filtered_default = filter_indicators(filter_test_indicators)
    print(f"Default filters (conf>=85, levels=['high','critical'], types=['ip','domain']): {len(filtered_default)}")
    for ind in filtered_default:
        print(f"  ✓ {ind['id']}: {ind['type']} (conf:{ind['confidence']}, level:{ind['threat_level']})")

    # Custom filters: lower confidence, include medium level
    filtered_custom = filter_indicators(filter_test_indicators, min_conf=70, levels=["medium", "high", "critical"], types=["ip", "domain", "url"])
    print(f"\nCustom filters (conf>=70, levels=['medium','high','critical'], types=['ip','domain','url']): {len(filtered_custom)}")
    for ind in filtered_custom:
        print(f"  ✓ {ind['id']}: {ind['type']} (conf:{ind['confidence']}, level:{ind['threat_level']})")

    # Strict filters: only critical, only IPs
    filtered_strict = filter_indicators(filter_test_indicators, min_conf=90, levels=["critical"], types=["ip"])
    print(f"\nStrict filters (conf>=90, levels=['critical'], types=['ip']): {len(filtered_strict)}")
    for ind in filtered_strict:
        print(f"  ✓ {ind['id']}: {ind['type']} (conf:{ind['confidence']}, level:{ind['threat_level']})")

    # Create sample processed indicators for output formats
    sample_indicators = [
        {"type": "ip", "value": "203.0.113.10", "confidence": 95, "threat_level": "critical", "sources": ["vendor_a", "vendor_c"]},
        {"type": "domain", "value": "malicious-example.com", "confidence": 94, "threat_level": "critical", "sources": ["vendor_c", "vendor_b"]},
        {"type": "ip", "value": "198.51.100.45", "confidence": 85, "threat_level": "high", "sources": ["vendor_b"]},
        {"type": "hash", "value": "5f4dcc3b5aa765d61d8327deb882cf99", "confidence": 88, "threat_level": "high", "sources": ["vendor_a", "vendor_b"]},
    ]

    print("\n=== Output Format Generation ===")

    # Generate firewall format
    firewall_data = transform_to_firewall(sample_indicators)
    with open("firewall_blocklist.json", "w") as f:
        json.dump(firewall_data, f, indent=2)
    print(f"✓ Created firewall_blocklist.json with {firewall_data['total_entries']} entries")

    # Generate SIEM format
    siem_data = transform_to_siem(sample_indicators)
    with open("siem_feed.json", "w") as f:
        json.dump(siem_data, f, indent=2)
    print(f"✓ Created siem_feed.json with {siem_data['event_count']} events")

    # Generate text report
    text_report = transform_to_text_report(sample_indicators)
    with open("summary_report.txt", "w") as f:
        f.write(text_report)
    print("✓ Created summary_report.txt")

    print("\nOutput files generated successfully!")

    # Test collections.Counter analysis
    analysis_indicators = [
        {"type": "ip", "threat_level": "critical", "sources": ["vendor_a", "vendor_c"], "value": "203.0.113.10"},
        {"type": "domain", "threat_level": "critical", "sources": ["vendor_c", "vendor_b"], "value": "malicious-example.com"},
        {"type": "ip", "threat_level": "high", "sources": ["vendor_b"], "value": "198.51.100.45"},
        {"type": "hash", "threat_level": "high", "sources": ["vendor_a", "vendor_b"], "value": "5f4dcc3b5aa765d61d8327deb882cf99"},
        {"type": "url", "threat_level": "medium", "sources": ["vendor_a"], "value": "http://evil.com/malware"},
        {"type": "ip", "threat_level": "critical", "sources": ["vendor_a"], "value": "192.168.1.100"},
        {"type": "domain", "threat_level": "high", "sources": ["vendor_c", "vendor_b"], "value": "bad-domain.net"},
    ]

    print("\n=== Collections.Counter Analysis ===")
    type_counts, threat_counts, source_counts = analyze_indicators_with_counter(analysis_indicators)

    print("1. Distribution by Type:")
    for indicator_type, count in sorted(type_counts.items()):
        print(f"   {indicator_type}: {count}")

    print("\n2. Distribution by Threat Level:")
    for threat_level, count in sorted(threat_counts.items()):
        print(f"   {threat_level}: {count}")

    print("\n3. Unique Indicators by Source:")
    for source, count in sorted(source_counts.items()):
        print(f"   {source}: {count} unique indicators")
