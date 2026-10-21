import unittest

from soc_research_lab import detect_anomalies, load_events, summarize_by_host


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            {"host": "web-01", "severity": 3},
            {"host": "web-01", "severity": 6},
            {"host": "db-01", "severity": 2},
            {"host": "db-01", "severity": 1},
            {"host": "app-01", "severity": 1},
            {"host": "app-01", "severity": 1},
            {"host": "app-01", "severity": 1},
        ]

    def test_summarize_by_host(self):
        summary = summarize_by_host(self.events)
        self.assertEqual(summary[0]["host"], "app-01")
        self.assertEqual(summary[0]["event_count"], 3)

    def test_detect_anomalies(self):
        anomalies = detect_anomalies(self.events, threshold=0.5)
        self.assertTrue(any(item["host"] == "web-01" for item in anomalies))

    def test_load_events(self):
        data = load_events("data/synthetic_endpoint_telemetry.csv")
        self.assertGreater(len(data), 10)
        self.assertEqual(data[0]["host"], "web-01")


if __name__ == "__main__":
    unittest.main()
