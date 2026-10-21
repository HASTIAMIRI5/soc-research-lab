#!/usr/bin/env python3
"""Command-line interface for the SOC Research Lab."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .telemetry import build_security_summary, detect_anomalies, load_events


def _print_summary(summary: dict) -> None:
    print("SOC Research Lab summary")
    print("=" * 28)
    print(f"Total events: {summary['total_events']}")
    print(f"Unique hosts: {summary['unique_hosts']}")
    print(f"Unique users: {summary['unique_users']}")

    print("\nTop hosts:")
    for host in summary["host_summary"][:5]:
        print(
            f"- {host['host']}: {host['event_count']} events, avg severity {host['avg_severity']}, "
            f"max severity {host['max_severity']}"
        )

    print("\nRisky processes:")
    risky = summary["risky_processes"][:5]
    if not risky:
        print("No elevated-risk processes detected.")
    else:
        for process in risky:
            print(
                f"- {process['process']}: {process['risk_events']} risk events, "
                f"max severity {process['max_severity']}"
            )


def _print_anomalies(csv_path: str, threshold: float) -> None:
    events = load_events(csv_path)
    anomalies = detect_anomalies(events, threshold=threshold)
    print(f"Anomalies for {csv_path} (threshold={threshold})")
    print("=" * 52)
    if not anomalies:
        print("No anomalies detected.")
        return

    for item in anomalies:
        print(
            f"- {item['host']}: {item['event_count']} events vs median baseline {item['baseline']} "
            f"(score={item['anomaly_score']})"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze SOC telemetry for suspicious patterns.")
    parser.add_argument("--csv", type=str, default="data/synthetic_endpoint_telemetry.csv", help="Path to a CSV telemetry dataset")
    parser.add_argument("--summary", action="store_true", help="Print a full summary of host, user, and process activity")
    parser.add_argument("--anomalies", action="store_true", help="Print host anomalies based on event count variance")
    parser.add_argument("--threshold", type=float, default=0.75, help="Threshold for anomaly detection score")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    csv_path = Path(args.csv)
    if not csv_path.exists():
        parser.error(f"CSV file not found: {csv_path}")

    if args.summary:
        _print_summary(build_security_summary(load_events(csv_path)))
        return 0

    if args.anomalies:
        _print_anomalies(str(csv_path), args.threshold)
        return 0

    _print_summary(build_security_summary(load_events(csv_path)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
