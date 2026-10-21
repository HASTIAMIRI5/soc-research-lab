#!/usr/bin/env python3
"""Demo runner for the SOC Research Lab."""

from pathlib import Path

from soc_research_lab import build_security_summary, load_events


def main() -> None:
    data_path = Path(__file__).resolve().parents[1] / "data" / "synthetic_endpoint_telemetry.csv"
    events = load_events(data_path)
    summary = build_security_summary(events)

    print("SOC Research Lab demo")
    print("=" * 24)
    print(f"Total events: {summary['total_events']}")
    print(f"Unique hosts: {summary['unique_hosts']}")
    print(f"Unique users: {summary['unique_users']}")

    print("\nHost summary:")
    for host in summary["host_summary"]:
        print(f"- {host['host']}: {host['event_count']} events, avg severity {host['avg_severity']}")

    print("\nRisky processes:")
    for process in summary["risky_processes"][:5]:
        print(f"- {process['process']}: {process['risk_events']} risk events, max severity {process['max_severity']}")

    print("\nAnomalous hosts:")
    if not summary["anomalies"]:
        print("No anomalies detected for the current sample dataset.")
    else:
        for item in summary["anomalies"]:
            print(f"- {item['host']}: {item['event_count']} events vs baseline {item['baseline']} (score={item['anomaly_score']})")


if __name__ == "__main__":
    main()
