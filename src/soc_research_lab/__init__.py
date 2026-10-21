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
        rows: List[Dict[str, Any]] = []
        for row in reader:
            rows.append(
                {
                    "timestamp": row.get("timestamp"),
                    "host": row.get("host", "unknown"),
                    "user": row.get("user", "unknown"),
                    "event_type": row.get("event_type", "unknown"),
                    "severity": int(row.get("severity", 0) or 0),
                    "source_ip": row.get("source_ip", "unknown"),
                    "process_name": row.get("process_name", "unknown"),
                    "status": row.get("status", "unknown"),
                }
            )
    return rows


def summarize_by_host(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Aggregate event volume and severity by host."""
    host_stats: Dict[str, Dict[str, Any]] = {}

    for event in events:
        host = event.get("host", "unknown")
        stats = host_stats.setdefault(
            host,
            {
                "host": host,
                "event_count": 0,
                "severity_total": 0,
                "max_severity": 0,
                "users": set(),
            },
        )
        stats["event_count"] += 1
        severity = int(event.get("severity", 0) or 0)
        stats["severity_total"] += severity
        stats["max_severity"] = max(stats["max_severity"], severity)
        stats["users"].add(str(event.get("user", "unknown")))

    summary: List[Dict[str, Any]] = []
    for host, stats in sorted(host_stats.items()):
        event_count = stats["event_count"]
        avg_severity = stats["severity_total"] / event_count if event_count else 0.0
        summary.append(
            {
                "host": host,
                "event_count": event_count,
                "avg_severity": round(avg_severity, 2),
                "max_severity": stats["max_severity"],
                "user_count": len(stats["users"]),
            }
        )
    return summary


def summarize_by_user(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Aggregate activity by user across hosts."""
    user_stats: Dict[str, Dict[str, Any]] = {}

    for event in events:
        user = str(event.get("user", "unknown"))
        stats = user_stats.setdefault(
            user,
            {"user": user, "event_count": 0, "severity_total": 0, "host_count": set()},
        )
        stats["event_count"] += 1
        stats["severity_total"] += int(event.get("severity", 0) or 0)
        stats["host_count"].add(str(event.get("host", "unknown")))

    summary: List[Dict[str, Any]] = []
    for user, stats in sorted(user_stats.items()):
        event_count = stats["event_count"]
        summary.append(
            {
                "user": user,
                "event_count": event_count,
                "avg_severity": round(stats["severity_total"] / event_count, 2) if event_count else 0.0,
                "host_count": len(stats["host_count"]),
            }
        )
    return summary


def summarize_by_process(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Summarize process activity and severity patterns."""
    process_stats: Dict[str, Dict[str, Any]] = {}

    for event in events:
        process_name = str(event.get("process_name", "unknown"))
        stats = process_stats.setdefault(
            process_name,
            {"process": process_name, "event_count": 0, "severity_total": 0, "max_severity": 0},
        )
        severity = int(event.get("severity", 0) or 0)
        stats["event_count"] += 1
        stats["severity_total"] += severity
        stats["max_severity"] = max(stats["max_severity"], severity)

    summary: List[Dict[str, Any]] = []
    for process_name, stats in sorted(process_stats.items()):
        event_count = stats["event_count"]
        summary.append(
            {
                "process": process_name,
                "event_count": event_count,
                "avg_severity": round(stats["severity_total"] / event_count, 2) if event_count else 0.0,
                "max_severity": stats["max_severity"],
            }
        )
    return summary


def detect_anomalies(events: Iterable[Dict[str, Any]], threshold: float = 2.0) -> List[Dict[str, Any]]:
    """Detect hosts whose event volume deviates significantly from the median baseline."""
    host_counts: Dict[str, int] = defaultdict(int)
    for event in events:
        host_counts[str(event.get("host", "unknown"))] += 1

    counts = list(host_counts.values())
    if not counts:
        return []

    baseline = statistics.median(counts)
    if not baseline:
        baseline = 1

    deviations: List[Dict[str, Any]] = []
    for host, count in sorted(host_counts.items()):
        delta = abs(count - baseline)
        score = delta / max(baseline, 1)
        if score >= threshold:
            deviations.append(
                {
                    "host": host,
                    "event_count": count,
                    "baseline": baseline,
                    "anomaly_score": round(score, 3),
                }
            )

    return deviations


def detect_risky_processes(events: Iterable[Dict[str, Any]], severity_threshold: int = 6) -> List[Dict[str, Any]]:
    """Return processes associated with elevated severity or repeated risky events."""
    process_stats: Dict[str, Dict[str, Any]] = {}

    for event in events:
        process_name = str(event.get("process_name", "unknown"))
        stats = process_stats.setdefault(
            process_name,
            {"process": process_name, "event_count": 0, "max_severity": 0, "risk_events": 0},
        )
        severity = int(event.get("severity", 0) or 0)
        stats["event_count"] += 1
        stats["max_severity"] = max(stats["max_severity"], severity)
        if severity >= severity_threshold:
            stats["risk_events"] += 1

    risky = [
        {
            "process": process_name,
            "event_count": stats["event_count"],
            "max_severity": stats["max_severity"],
            "risk_events": stats["risk_events"],
        }
        for process_name, stats in sorted(process_stats.items())
        if stats["risk_events"] > 0 or stats["max_severity"] >= severity_threshold
    ]
    return sorted(risky, key=lambda item: (-item["risk_events"], -item["max_severity"], item["process"]))


def build_security_summary(events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a compact security summary from a telemetry set."""
    event_list = list(events)
    return {
        "total_events": len(event_list),
        "unique_hosts": len({str(event.get("host", "unknown")) for event in event_list}),
        "unique_users": len({str(event.get("user", "unknown")) for event in event_list}),
        "host_summary": summarize_by_host(event_list),
        "user_summary": summarize_by_user(event_list),
        "process_summary": summarize_by_process(event_list),
        "anomalies": detect_anomalies(event_list),
        "risky_processes": detect_risky_processes(event_list),
    }
