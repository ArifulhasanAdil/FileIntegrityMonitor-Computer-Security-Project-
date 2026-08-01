import tempfile
import unittest
from pathlib import Path

from fim_engine import FileIntegrityMonitor, create_baseline
from gui import build_report_content, parse_audit_log_entry


class AuditLogParsingTests(unittest.TestCase):
    def test_parse_audit_log_entry_supports_dict_and_string_formats(self):
        entry_dict = {
            "timestamp": "2026-01-01 00:00:00",
            "event_type": "MODIFIED",
            "message": "MODIFIED: config.sys",
        }

        timestamp, event_type, message = parse_audit_log_entry(entry_dict)
        self.assertEqual(timestamp, "2026-01-01 00:00:00")
        self.assertEqual(event_type, "MODIFIED")
        self.assertEqual(message, "MODIFIED: config.sys")

        string_entry = "[2026-01-01 00:00:00] Monitoring started"
        timestamp, event_type, message = parse_audit_log_entry(string_entry)
        self.assertEqual(timestamp, "2026-01-01 00:00:00")
        self.assertEqual(event_type, "MONITORING_STARTED")
        self.assertEqual(message, "Monitoring started")

    def test_build_report_content_includes_summary_and_audit_events(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            monitor_dir = root / "monitored_files"
            monitor_dir.mkdir()
            baseline_path = root / "baseline.json"
            (monitor_dir / "config.sys").write_text("VERSION=1.0", encoding="utf-8")
            create_baseline(monitor_dir, baseline_path)

            monitor = FileIntegrityMonitor(monitor_dir, baseline_path)
            summary = monitor.check_integrity()
            event_log = ["[2026-01-01 00:00:00] Monitoring started", "[2026-01-01 00:00:01] MODIFIED: config.sys"]

            report_text = build_report_content(summary, monitor, event_log)

            self.assertIn("File Integrity Monitoring System - Security Report", report_text)
            self.assertIn("Security Status:", report_text)
            self.assertIn("Total Files:", report_text)
            self.assertIn("Recent Audit Events", report_text)
            self.assertIn("Monitoring started", report_text)
            self.assertIn("config.sys", report_text)


if __name__ == "__main__":
    unittest.main()
