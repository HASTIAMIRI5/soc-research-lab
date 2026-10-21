#!/usr/bin/env python3
"""Demo runner for the SOC Research Lab."""

from pathlib import Path

from soc_research_lab import detect_anomalies, load_events, summarize_by_host


def main() -> None:
    data_path = Path(__file__).resolve().parents[1] / "data" / "synthetic_endpoint_telemetry.csv"
    events = load_events(data_path)

    print("SOC Research Lab demo")
    print("=" * 24)
    print("Host summary:")
    for host in summarize_by_host(events):
        print(f"- {host['host']}: {host['event_count']} events, avg severity {host['avg_severity']}")

    anomalies = detect_anomalies(events)
    print("\nAnomalous hosts:")
    if not anomalies:
        print("No anomalies detected for the current sample dataset.")
    else:
        for item in anomalies:
            print(f"- {item['host']}: {item['event_count']} events vs baseline {item['baseline']} (score={item['anomaly_score']})")


if __name__ == "__main__":
    main()
