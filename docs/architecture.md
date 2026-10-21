import unittest

from soc_research_lab import (
    build_security_summary,
    detect_anomalies,
    detect_risky_processes,
    load_events,
    summarize_by_host,
    summarize_by_process,
    summarize_by_user,
)


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            {"host": "web-01", "user": "svc_app", "process_name": "python.exe", "severity": 3},
            {"host": "web-01", "user": "svc_app", "process_name": "powershell.exe", "severity": 8},
            {"host": "db-01", "user": "svc_db", "process_name": "sqlservr.exe", "severity": 2},
            {"host": "db-01", "user": "svc_db", "process_name": "powershell.exe", "severity": 7},
            {"host": "app-01", "user": "svc_app", "process_name": "excel.exe", "severity": 1},
            {"host": "app-01", "user": "svc_app", "process_name": "excel.exe", "severity": 1},
            {"host": "app-01", "user": "svc_app", "process_name": "excel.exe", "severity": 1},
        ]

    def test_summarize_by_host(self):
        summary = summarize_by_host(self.events)
        self.assertEqual(summary[0]["host"], "app-01")
        self.assertEqual(summary[0]["event_count"], 3)

    def test_summarize_by_user(self):
        summary = summarize_by_user(self.events)
        self.assertTrue(any(item["user"] == "svc_app" for item in summary))

    def test_summarize_by_process(self):
        summary = summarize_by_process(self.events)
        self.assertTrue(any(item["process"] == "powershell.exe" for item in summary))

    def test_detect_anomalies(self):
        anomalies = detect_anomalies(self.events, threshold=0.5)
        self.assertTrue(any(item["host"] == "web-01" for item in anomalies))

    def test_detect_risky_processes(self):
        risky = detect_risky_processes(self.events)
        self.assertTrue(any(item["process"] == "powershell.exe" for item in risky))

    def test_build_security_summary(self):
        summary = build_security_summary(self.events)
        self.assertEqual(summary["total_events"], 7)
        self.assertGreater(len(summary["anomalies"]), 0)

    def test_load_events(self):
        data = load_events("data/synthetic_endpoint_telemetry.csv")
        self.assertGreater(len(data), 10)
        self.assertEqual(data[0]["host"], "web-01")


if __name__ == "__main__":
    unittest.main()
