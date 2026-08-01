import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def compute_event_hash(timestamp: str, event_type: str, message: str, previous_hash: str) -> str:
    """Compute the SHA-256 hash for a tamper-evident audit event."""
    payload = f"{timestamp}|{event_type}|{message}|{previous_hash}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def verify_event_log_integrity(event_log_path: Optional[Path] = None) -> Tuple[bool, str]:
    """Verify the integrity of the audit log hash chain."""
    if event_log_path is None:
        event_log_path = Path("event_log.json")

    if not event_log_path.exists():
        return False, "Audit log file not found"

    try:
        with event_log_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, OSError):
        return False, "Audit log is unreadable or invalid"

    if not isinstance(data, list):
        return False, "Audit log format is invalid"

    if not data:
        return True, "Audit log integrity verified"

    previous_hash = "GENESIS"
    for entry in data:
        if not isinstance(entry, dict):
            return False, "Audit log tampering detected"

        timestamp = str(entry.get("timestamp", ""))
        event_type = str(entry.get("event_type", ""))
        message = str(entry.get("message", ""))
        stored_previous_hash = str(entry.get("previous_hash", ""))
        stored_event_hash = str(entry.get("event_hash", ""))

        expected_previous_hash = previous_hash
        if stored_previous_hash != expected_previous_hash:
            return False, "Audit log tampering detected"

        expected_event_hash = compute_event_hash(timestamp, event_type, message, previous_hash)
        if expected_event_hash != stored_event_hash:
            return False, "Audit log tampering detected"

        previous_hash = stored_event_hash

    return True, "Audit log integrity verified"


def migrate_event_log(event_log_path: Optional[Path] = None) -> List[Dict[str, str]]:
    """Upgrade older event log entries into the hash-chain format."""
    if event_log_path is None:
        event_log_path = Path("event_log.json")

    if not event_log_path.exists():
        return []

    try:
        with event_log_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    migrated: List[Dict[str, str]] = []
    previous_hash = "GENESIS"
    for entry in data:
        if not isinstance(entry, dict):
            continue

        timestamp = str(entry.get("timestamp", ""))
        event_type = str(entry.get("event_type", ""))
        message = str(entry.get("message", ""))
        event_hash = compute_event_hash(timestamp, event_type, message, previous_hash)
        migrated.append(
            {
                "timestamp": timestamp,
                "event_type": event_type,
                "message": message,
                "previous_hash": previous_hash,
                "event_hash": event_hash,
            }
        )
        previous_hash = event_hash

    return migrated


class FileIntegrityMonitor:
    """Simple file integrity monitor that uses SHA-256 hashes."""

    def __init__(self, monitor_dir="monitored_files", baseline_path="baseline.json"):
        self.monitor_dir = Path(monitor_dir)
        self.baseline_path = Path(baseline_path)

    def check_integrity(self) -> Dict[str, object]:
        """Compare the monitored files against the baseline and return a summary for the GUI."""
        report = verify_integrity(self.monitor_dir, self.baseline_path)
        changes = report.get("changes", [])

        summary = {
            "status": report.get("status", "safe"),
            "total_files": self._count_files(),
            "safe_count": self._count_safe_files(changes),
            "modified_count": self._count_by_type(changes, "modified"),
            "new_count": self._count_by_type(changes, "new"),
            "deleted_count": self._count_by_type(changes, "deleted"),
            "changes": changes,
        }
        return summary

    def _count_files(self) -> int:
        if not self.monitor_dir.exists():
            return 0
        return sum(1 for path in self.monitor_dir.iterdir() if path.is_file())

    def _count_safe_files(self, changes: List[Dict[str, object]]) -> int:
        total_files = self._count_files()
        changed_files = {change.get("file") for change in changes if isinstance(change, dict) and "file" in change}
        return max(total_files - len(changed_files), 0)

    def _count_by_type(self, changes: List[Dict[str, object]], change_type: str) -> int:
        return sum(1 for change in changes if isinstance(change, dict) and change.get("type") == change_type)

    def get_file_details(self, filename: str) -> Dict[str, object]:
        """Return comparison details for a specific file from the baseline."""
        monitor_path = self.monitor_dir
        baseline_file = self.baseline_path

        if not monitor_path.exists():
            return {
                "file_name": filename,
                "status": "DELETED",
                "original_hash": "",
                "current_hash": "",
                "comparison_result": "FILE DELETED - CURRENT HASH UNAVAILABLE",
            }

        if not baseline_file.exists():
            raise FileNotFoundError(f"Baseline file not found: {baseline_file}")

        with baseline_file.open("r", encoding="utf-8") as handle:
            baseline_data = json.load(handle)

        file_path = monitor_path / filename
        if not file_path.exists():
            return {
                "file_name": filename,
                "status": "DELETED",
                "original_hash": baseline_data.get(filename, ""),
                "current_hash": "",
                "comparison_result": "FILE DELETED - CURRENT HASH UNAVAILABLE",
            }

        current_hash = calculate_hash(file_path)
        original_hash = baseline_data.get(filename, "")

        if not original_hash:
            return {
                "file_name": filename,
                "status": "NEW",
                "original_hash": "",
                "current_hash": current_hash,
                "comparison_result": "NEW FILE - NO TRUSTED BASELINE",
            }

        if current_hash == original_hash:
            return {
                "file_name": filename,
                "status": "SAFE",
                "original_hash": original_hash,
                "current_hash": current_hash,
                "comparison_result": "INTEGRITY VERIFIED",
            }

        return {
            "file_name": filename,
            "status": "MODIFIED",
            "original_hash": original_hash,
            "current_hash": current_hash,
            "comparison_result": "HASH MISMATCH - FILE MODIFIED",
        }


def calculate_hash(file_path: Path) -> str:
    """Calculate the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def create_baseline(monitor_dir, baseline_path) -> Dict[str, str]:
    """Create a trusted baseline from the files currently in the monitored directory."""
    monitor_path = Path(monitor_dir)
    baseline_file = Path(baseline_path)

    monitor_path.mkdir(parents=True, exist_ok=True)
    baseline_file.parent.mkdir(parents=True, exist_ok=True)

    baseline: Dict[str, str] = {}
    for file_path in sorted(monitor_path.iterdir()):
        if file_path.is_file():
            baseline[file_path.name] = calculate_hash(file_path)

    with baseline_file.open("w", encoding="utf-8") as handle:
        json.dump(baseline, handle, indent=4)

    return baseline


def verify_integrity(monitor_dir, baseline_path) -> Dict[str, object]:
    """Compare the monitored files against a trusted baseline and report changes."""
    monitor_path = Path(monitor_dir)
    baseline_file = Path(baseline_path)

    monitor_path.mkdir(parents=True, exist_ok=True)

    if not baseline_file.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_file}")

    with baseline_file.open("r", encoding="utf-8") as handle:
        saved_baseline = json.load(handle)

    changes: List[Dict[str, object]] = []

    for filename, expected_hash in saved_baseline.items():
        file_path = monitor_path / filename

        if not file_path.exists():
            changes.append({"type": "deleted", "file": filename})
        else:
            current_hash = calculate_hash(file_path)
            if current_hash != expected_hash:
                changes.append(
                    {
                        "type": "modified",
                        "file": filename,
                        "expected": expected_hash,
                        "current": current_hash,
                    }
                )

    for file_path in sorted(monitor_path.iterdir()):
        if file_path.is_file() and file_path.name not in saved_baseline:
            changes.append({"type": "new", "file": file_path.name})

    return {
        "status": "safe" if not changes else "warning",
        "changes": changes,
    }


def classify_realtime_event(event_type: str, file_path: Path, monitor_dir, baseline_path) -> Dict[str, object]:
    """Classify a filesystem event using the existing SHA-256 baseline rules."""
    monitor_path = Path(monitor_dir)
    baseline_file = Path(baseline_path)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not monitor_path.exists():
        monitor_path.mkdir(parents=True, exist_ok=True)

    baseline_data: Dict[str, str] = {}
    if baseline_file.exists():
        with baseline_file.open("r", encoding="utf-8") as handle:
            baseline_data = json.load(handle)

    file_name = file_path.name
    classification = "SAFE"
    severity = "LOW"

    if event_type == "deleted":
        classification = "DELETED"
        severity = "HIGH"
    elif event_type == "created":
        if file_name in baseline_data:
            current_hash = calculate_hash(file_path)
            if current_hash == baseline_data[file_name]:
                classification = "SAFE"
                severity = "LOW"
            else:
                classification = "MODIFIED"
                severity = "HIGH"
        else:
            classification = "NEW"
            severity = "LOW"
    elif event_type == "modified":
        if not file_path.exists():
            classification = "DELETED"
            severity = "HIGH"
        else:
            current_hash = calculate_hash(file_path)
            if file_name in baseline_data and current_hash != baseline_data[file_name]:
                classification = "MODIFIED"
                severity = "HIGH"
            elif file_name not in baseline_data:
                classification = "NEW"
                severity = "LOW"
            else:
                classification = "SAFE"
                severity = "LOW"
    elif event_type == "moved":
        classification = "MODIFIED"
        severity = "MEDIUM"

    return {
        "event_type": event_type,
        "file_name": file_name,
        "classification": classification,
        "severity": severity,
        "timestamp": timestamp,
        "current_hash": calculate_hash(file_path) if file_path.exists() and file_path.is_file() else "",
    }


def build_realtime_event_message(event: Dict[str, object]) -> str:
    """Create a message that matches the existing GUI log format."""
    event_type = str(event.get("event_type", ""))
    file_name = str(event.get("file_name", ""))
    classification = str(event.get("classification", "SAFE"))
    severity = str(event.get("severity", "LOW"))
    timestamp = str(event.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    return f"[{timestamp}] {classification} | {event_type.upper()} | {file_name} | SEVERITY={severity}"
