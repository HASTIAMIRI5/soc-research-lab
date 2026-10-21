from __future__ import annotations

import csv
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List


def load_events(csv_path: str | Path) -> List[Dict[str, Any]]:
    """Load a telemetry CSV file into a list of dictionaries."""
    path = Path(csv_path)
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = []
        for row in reader:
            rows.append({
                "timestamp": row.get("timestamp"),
                "host": row.get("host", "unknown"),
                "user": row.get("user", "unknown"),
                "event_type": row.get("event_type", "unknown"),
                "severity": int(row.get("severity", 0)),
                "source_ip": row.get("source_ip", "unknown"),
                "process_name": row.get("process_name", "unknown"),
                "status": row.get("status", "unknown"),
            })
    return rows


def summarize_by_host(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Aggregate event volume and severity by host."""
    counts: Dict[str, int] = defaultdict(int)
    severities: Dict[str, List[int]] = defaultdict(list)

    for event in events:
        host = event.get("host", "unknown")
        counts[host] += 1
        severities[host].append(int(event.get("severity", 0)))

    summary = []
    for host, count in sorted(counts.items()):
        values = severities[host]
        average = sum(values) / len(values)
        summary.append({
            "host": host,
            "event_count": count,
            "avg_severity": round(average, 2),
            "max_severity": max(values),
        })
    return summary


def detect_anomalies(events: Iterable[Dict[str, Any]], threshold: float = 2.0) -> List[Dict[str, Any]]:
    """Detect hosts whose event volume deviates significantly from the median baseline."""
    host_counts: Dict[str, int] = defaultdict(int)
    for event in events:
        host_counts[event.get("host", "unknown")] += 1

    counts = list(host_counts.values())
    if not counts:
        return []

    baseline = statistics.median(counts)
    if not baseline:
        baseline = 1

    deviations = []
    for host, count in sorted(host_counts.items()):
        delta = abs(count - baseline)
        score = delta / max(baseline, 1)
        if score >= threshold:
            deviations.append({
                "host": host,
                "event_count": count,
                "baseline": baseline,
                "anomaly_score": round(score, 3),
            })

    return deviations
