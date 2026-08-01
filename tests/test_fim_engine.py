import tempfile
import unittest
from pathlib import Path

from fim_engine import (
    FileIntegrityMonitor,
    classify_realtime_event,
    compute_event_hash,
    create_baseline,
    migrate_event_log,
    verify_event_log_integrity,
    verify_integrity,
)


class FileIntegrityMonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.monitor_dir = self.root / "monitored_files"
        self.monitor_dir.mkdir()
        (self.monitor_dir / "config.sys").write_text("VERSION=1.0.4\nALLOW_ACCESS=FALSE", encoding="utf-8")
        (self.monitor_dir / "database.db").write_text("USER_DATA_ENCRYPTED_BLOB", encoding="utf-8")
        self.baseline_path = self.root / "baseline.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_create_baseline_and_detect_changes(self):
        create_baseline(self.monitor_dir, self.baseline_path)

        self.assertTrue(self.baseline_path.exists())

        report = verify_integrity(self.monitor_dir, self.baseline_path)
        self.assertEqual(report["status"], "safe")
        self.assertEqual(report["changes"], [])

        (self.monitor_dir / "config.sys").write_text("VERSION=2.0.0", encoding="utf-8")
        (self.monitor_dir / "app.exe").write_text("BINARY_EXEC_MOCK_DATA", encoding="utf-8")
        (self.monitor_dir / "database.db").unlink()

        report = verify_integrity(self.monitor_dir, self.baseline_path)
        self.assertEqual(report["status"], "warning")
        self.assertGreaterEqual(len(report["changes"]), 3)
        self.assertTrue(any(change["type"] == "modified" for change in report["changes"]))
        self.assertTrue(any(change["type"] == "new" for change in report["changes"]))
        self.assertTrue(any(change["type"] == "deleted" for change in report["changes"]))

        monitor = FileIntegrityMonitor(self.monitor_dir, self.baseline_path)
        summary = monitor.check_integrity()
        self.assertEqual(summary["status"], "warning")
        self.assertEqual(summary["total_files"], 2)
        self.assertEqual(summary["modified_count"], 1)
        self.assertEqual(summary["new_count"], 1)
        self.assertEqual(summary["deleted_count"], 1)

    def test_get_file_details_provides_hash_comparison(self):
        create_baseline(self.monitor_dir, self.baseline_path)
        monitor = FileIntegrityMonitor(self.monitor_dir, self.baseline_path)

        details = monitor.get_file_details("config.sys")
        self.assertEqual(details["status"], "SAFE")
        self.assertEqual(details["comparison_result"], "INTEGRITY VERIFIED")
        self.assertEqual(details["original_hash"], details["current_hash"])

    def test_classify_realtime_event_for_new_file(self):
        create_baseline(self.monitor_dir, self.baseline_path)

        new_path = self.monitor_dir / "new.log"
        new_path.write_text("new-content", encoding="utf-8")

        event = classify_realtime_event("created", new_path, self.monitor_dir, self.baseline_path)
        self.assertEqual(event["classification"], "NEW")
        self.assertEqual(event["severity"], "LOW")
        self.assertEqual(event["event_type"], "created")
        self.assertEqual(event["file_name"], "new.log")

    def test_classify_realtime_event_for_modified_file(self):
        create_baseline(self.monitor_dir, self.baseline_path)

        target_path = self.monitor_dir / "config.sys"
        target_path.write_text("VERSION=2.0.0", encoding="utf-8")

        event = classify_realtime_event("modified", target_path, self.monitor_dir, self.baseline_path)
        self.assertEqual(event["classification"], "MODIFIED")
        self.assertEqual(event["severity"], "HIGH")
        self.assertEqual(event["event_type"], "modified")
        self.assertEqual(event["file_name"], "config.sys")

    def test_verify_event_log_integrity_for_valid_chain(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "event_log.json"
            entries = [
                {"timestamp": "t1", "event_type": "INFO", "message": "first", "previous_hash": "GENESIS", "event_hash": compute_event_hash("t1", "INFO", "first", "GENESIS")},
                {"timestamp": "t2", "event_type": "INFO", "message": "second", "previous_hash": compute_event_hash("t1", "INFO", "first", "GENESIS"), "event_hash": compute_event_hash("t2", "INFO", "second", compute_event_hash("t1", "INFO", "first", "GENESIS"))},
            ]
            log_path.write_text(__import__("json").dumps(entries), encoding="utf-8")
            is_valid, detail = verify_event_log_integrity(log_path)
            self.assertTrue(is_valid)
            self.assertIn("verified", detail.lower())

    def test_verify_event_log_integrity_detects_modified_event_data(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "event_log.json"
            entries = [
                {"timestamp": "t1", "event_type": "INFO", "message": "first", "previous_hash": "GENESIS", "event_hash": compute_event_hash("t1", "INFO", "first", "GENESIS")},
            ]
            entries[0]["message"] = "tampered"
            log_path.write_text(__import__("json").dumps(entries), encoding="utf-8")
            is_valid, detail = verify_event_log_integrity(log_path)
            self.assertFalse(is_valid)
            self.assertIn("tampering", detail.lower())

    def test_verify_event_log_integrity_detects_modified_event_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "event_log.json"
            entries = [
                {"timestamp": "t1", "event_type": "INFO", "message": "first", "previous_hash": "GENESIS", "event_hash": compute_event_hash("t1", "INFO", "first", "GENESIS")},
            ]
            entries[0]["event_hash"] = "bad-hash"
            log_path.write_text(__import__("json").dumps(entries), encoding="utf-8")
            is_valid, detail = verify_event_log_integrity(log_path)
            self.assertFalse(is_valid)
            self.assertIn("tampering", detail.lower())

    def test_verify_event_log_integrity_detects_broken_previous_hash_link(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "event_log.json"
            entries = [
                {"timestamp": "t1", "event_type": "INFO", "message": "first", "previous_hash": "GENESIS", "event_hash": compute_event_hash("t1", "INFO", "first", "GENESIS")},
                {"timestamp": "t2", "event_type": "INFO", "message": "second", "previous_hash": "wrong", "event_hash": compute_event_hash("t2", "INFO", "second", "wrong")},
            ]
            log_path.write_text(__import__("json").dumps(entries), encoding="utf-8")
            is_valid, detail = verify_event_log_integrity(log_path)
            self.assertFalse(is_valid)
            self.assertIn("tampering", detail.lower())

    def test_verify_event_log_integrity_for_empty_log(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "event_log.json"
            log_path.write_text("[]", encoding="utf-8")
            is_valid, detail = verify_event_log_integrity(log_path)
            self.assertTrue(is_valid)
            self.assertIn("verified", detail.lower())

    def test_migrate_event_log_and_clear_chain_reset(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "event_log.json"
            old_entries = [{"timestamp": "t1", "event_type": "INFO", "message": "legacy"}]
            log_path.write_text(__import__("json").dumps(old_entries), encoding="utf-8")

            migrated = migrate_event_log(log_path)
            self.assertEqual(len(migrated), 1)
            self.assertEqual(migrated[0]["previous_hash"], "GENESIS")
            self.assertTrue(migrated[0]["event_hash"])


if __name__ == "__main__":
    unittest.main()
