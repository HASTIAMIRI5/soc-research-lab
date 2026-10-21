"""SOC Research Lab package."""

from .telemetry import (
    build_security_summary,
    detect_anomalies,
    detect_risky_processes,
    load_events,
    summarize_by_host,
    summarize_by_process,
    summarize_by_user,
)

__all__ = [
    "load_events",
    "summarize_by_host",
    "summarize_by_user",
    "summarize_by_process",
    "detect_anomalies",
    "detect_risky_processes",
    "build_security_summary",
]
