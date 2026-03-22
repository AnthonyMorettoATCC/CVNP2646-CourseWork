# Threat Intelligence Multi-Feed Aggregator

A Python-based threat intelligence aggregator that normalizes, deduplicates, and transforms threat indicators from multiple vendor feeds into standardized formats for different security tools.

## Overview

This aggregator processes threat intelligence from multiple vendors with different data schemas, normalizes them into a common format, removes duplicates while preserving the highest-confidence indicators, and outputs the aggregated data in three different formats suitable for various security systems.

### Why Three Different Feeds?

Real-world threat intelligence comes from diverse sources (commercial vendors, open-source feeds, internal sensors) that use different field names and data structures. This aggregator demonstrates:

- **Schema normalization**: Handling incompatible field names across vendors
- **Confidence-based deduplication**: Keeping the most reliable indicator when duplicates exist
- **Multi-format output**: Generating outputs for different security tools (firewalls, SIEM, reporting)

## Feed Schemas

Each vendor uses different field names for the same conceptual data:

| Concept | Vendor A | Vendor B | Vendor C | Normalized |
|---------|----------|----------|----------|------------|
| Type | `type` | `indicator_type` | `category` | `type` |
| Value | `value` | `indicator_value` | `ioc` | `value` |
| Confidence | `confidence` | `score` | `reliability` | `confidence` |
| Threat Level | `threat` | `severity` | `risk` | `threat_level` |
| Sources | `sources` | `sources` | `sources` | `sources` |
| Timestamp | `first_seen` | `detected_at` | `observed_at` | N/A |

### Sample Vendor Data

**Vendor A** (`vendor_a.json`):
```json
{
  "id": "va-001",
  "type": "ip",
  "value": "203.0.113.10",
  "confidence": 95,
  "threat": "critical",
  "first_seen": "2026-03-20T08:15:00Z",
  "tags": ["apt28", "ransomware"]
}
```

**Vendor B** (`vendor_b.json`):
```json
{
  "id": "vb-001",
  "indicator_type": "ip",
  "indicator_value": "203.0.113.10",
  "score": 80,
  "severity": "high",
  "source": "vendor_b",
  "detected_at": "2026-03-20T10:00:00Z"
}
```

**Vendor C** (`vendor_c.json`):
```json
{
  "id": "vc-001",
  "category": "ip",
  "ioc": "203.0.113.10",
  "reliability": 90,
  "risk": "high",
  "source": "vendor_c",
  "observed_at": "2026-03-20T12:00:00Z"
}
```

## Normalization Strategy

The `normalize_indicator()` function uses a **fallback approach** with `.get()` to handle different vendor schemas:

```python
def normalize_indicator(raw):
    t = raw.get("type") or raw.get("indicator_type") or raw.get("category")
    v = raw.get("value") or raw.get("indicator_value") or raw.get("ioc")
    confidence = raw.get("confidence") or raw.get("score") or raw.get("reliability")
    threat_level = raw.get("threat") or raw.get("severity") or raw.get("risk")

    return {
        "type": t if t is not None else "unknown",
        "value": v if v is not None else "",
        "confidence": confidence,
        "threat_level": threat_level,
        "sources": sources,
    }
```

**Key Features:**
- **Graceful fallbacks**: Tries multiple field names in priority order
- **Type safety**: Converts confidence to int when possible
- **Source handling**: Ensures sources is always a list
- **Default values**: Provides sensible defaults for missing fields

## Deduplication Logic

The `deduplicate_indicators()` function removes duplicates while preserving the most valuable intelligence.

### Duplicate Identification
- Uses `(type, value)` tuple as unique identifier
- Example: `("ip", "203.0.113.10")` identifies all instances of this IP

### Confidence-Based Selection
- **Higher confidence wins**: When duplicates found, keeps indicator with highest confidence score
- **None treated as 0**: Missing confidence values don't break comparison
- **Source merging**: Combines source lists from all duplicate instances

### Source Merging
```python
# Combine and deduplicate sources while preserving order
merged_sources = []
seen = set()
for source in existing_sources + current_sources:
    if source not in seen:
        seen.add(source)
        merged_sources.append(source)
```

## Test Data

The aggregator includes comprehensive test data to validate all functionality:

### Feed Contents
- **Vendor A**: 6 indicators (2 IPs, 2 domains, 1 hash, 1 URL)
- **Vendor B**: 6 indicators (same types, different confidence values)
- **Vendor C**: 6 indicators (same types, includes duplicates with A)

### Duplicate Analysis
**Cross-feed duplicates:**
- **IP `203.0.113.10`**: Appears in all 3 vendors (confidences: 95, 80, 90)
  - **Expected**: Keep Vendor A version (highest confidence: 95)
  - **Sources merged**: `["vendor_a", "vendor_b", "vendor_c"]`
- **Domain `malicious-example.com`**: Appears in Vendor A (92) and Vendor C (94)
  - **Expected**: Keep Vendor C version (higher confidence)
  - **Sources merged**: `["vendor_a", "vendor_c"]`
- **Hash `5f4dcc3b5aa765d61d8327deb882cf99`**: Appears in all 3 vendors
- **URL `http://203.0.113.77/malware.exe`**: Appears in all 3 vendors

**Expected deduplication results:**
- **Input**: 18 total indicators (6 × 3 vendors)
- **Duplicates removed**: ~8-10 (depending on exact matches)
- **Unique output**: ~8-10 indicators with merged sources

### Validation Test Cases
The `validate_indicators()` function tests:
- Missing required fields
- Invalid types (not in: ip, domain, hash, url)
- Confidence out of range (not 0-100)
- Empty values

## Output Formats

The aggregator generates three different output formats for different security tools:

### 1. Firewall Blocklist (`firewall_blocklist.json`)
**Purpose**: Direct import into firewall systems for automated blocking

**Structure**:
```json
{
  "generated_at": "2026-03-21T20:30:58.913996",
  "total_entries": 4,
  "blocklist": [
    {
      "address": "203.0.113.10",
      "action": "block",
      "priority": "high",
      "reason": "Threat level: critical, Confidence: 95%",
      "sources": ["vendor_a", "vendor_c"]
    }
  ]
}
```

### 2. SIEM Feed (`siem_feed.json`)
**Purpose**: Integration with Security Information and Event Management systems

**Structure**:
```json
{
  "feed_name": "aggregated_threat_intelligence",
  "feed_version": "1.0",
  "last_updated": "2026-03-21T20:30:58.914918",
  "event_count": 4,
  "events": [
    {
      "event_type": "threat_intelligence",
      "indicator_type": "ip",
      "indicator_value": "203.0.113.10",
      "severity_score": 95,
      "threat_category": "critical",
      "detection_sources": ["vendor_a", "vendor_c"],
      "timestamp": "2026-03-21T20:30:58.914899",
      "status": "active"
    }
  ]
}
```

### 3. Summary Report (`summary_report.txt`)
**Purpose**: Human-readable executive summary and detailed indicator listing

**Format**:
```
============================================================
THREAT INTELLIGENCE SUMMARY REPORT
============================================================
Generated: 2026-03-21 20:30:58
Total Indicators: 4

IP INDICATORS (2)
----------------------------------------
Value: 203.0.113.10
Confidence: 95%
Threat Level: critical
Sources: vendor_a, vendor_c

DOMAIN INDICATORS (1)
----------------------------------------
Value: malicious-example.com
Confidence: 94%
Threat Level: critical
Sources: vendor_c, vendor_b
```

## Usage

```bash
# Run all tests and generate outputs
python threat_aggregator.py

# The script will:
# 1. Test normalization from all vendor formats
# 2. Validate indicator quality
# 3. Test deduplication logic
# 4. Apply configurable filters
# 5. Generate all three output formats
# 6. Analyze distributions with collections.Counter
```

## Architecture

```
Raw Vendor Feeds → Normalization → Validation → Deduplication → Filtering → Output Formats
    ↓              ↓            ↓           ↓            ↓            ↓
vendor_a.json    normalize()  validate()  dedup()     filter()   firewall.json
vendor_b.json                 indicators               indicators  siem.json
vendor_c.json                                              indicators  report.txt
```

## Key Functions

- `normalize_indicator()`: Schema normalization with fallbacks
- `validate_indicators()`: Data quality checks
- `deduplicate_indicators()`: Confidence-based deduplication
- `filter_indicators()`: Configurable filtering
- `transform_to_firewall()`: Firewall blocklist format
- `transform_to_siem()`: SIEM event format
- `transform_to_text_report()`: Human-readable report
- `analyze_indicators_with_counter()`: Statistical analysis

This aggregator provides a complete pipeline for processing multi-vendor threat intelligence feeds, from ingestion to operational deployment across different security systems.</content>
<parameter name="filePath">c:\Users\moret.000\Documents\Python_Course\CVNP2646-CourseWork\week8\README.md