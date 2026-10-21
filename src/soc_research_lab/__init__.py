"""SOC Research Lab package."""

from .telemetry import detect_anomalies, load_events, summarize_by_host

__all__ = ["load_events", "summarize_by_host", "detect_anomalies"]
