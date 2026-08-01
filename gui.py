import json
import queue
import shutil
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from fim_engine import (
    FileIntegrityMonitor,
    build_realtime_event_message,
    calculate_hash,
    classify_realtime_event,
    create_baseline,
    migrate_event_log,
    verify_event_log_integrity,
)
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


def parse_audit_log_entry(entry):
    if isinstance(entry, dict):
        timestamp = str(entry.get("timestamp", ""))
        event_type = str(entry.get("event_type", "INFO"))
        message = str(entry.get("message", ""))
        return timestamp, event_type, message

    if not isinstance(entry, str):
        return "", "INFO", ""

    if entry.startswith("[") and "]" in entry:
        timestamp, remainder = entry.split("]", 1)
        timestamp = timestamp.strip("[")
        message = remainder.strip()
        return timestamp, FileIntegrityGUI._event_type_from_message_static(message), message

    return "", "INFO", str(entry)


def build_report_content(summary, monitor, event_log, audit_status=None):
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    monitor_dir = monitor.monitor_dir
    baseline_path = monitor.baseline_path

    current_files = {path.name for path in monitor_dir.iterdir() if path.is_file()} if monitor_dir.exists() else set()
    baseline_data = {}
    if baseline_path.exists():
        with baseline_path.open("r", encoding="utf-8") as handle:
            baseline_data = json.load(handle)

    files = sorted(set(current_files) | set(baseline_data.keys()))

    lines = [
        "File Integrity Monitoring System - Security Report",
        "=" * 52,
        f"Generation Timestamp: {generated_at}",
        f"Security Status: {summary.get('status', 'safe').upper()}",
        f"Audit Log Status: {audit_status or 'UNKNOWN'}",
        f"Total Files: {summary.get('total_files', 0)}",
        f"SAFE Count: {summary.get('safe_count', 0)}",
        f"MODIFIED Count: {summary.get('modified_count', 0)}",
        f"NEW Count: {summary.get('new_count', 0)}",
        f"DELETED Count: {summary.get('deleted_count', 0)}",
        "",
        "Detected File Inventory",
        "-" * 24,
    ]

    if not files:
        lines.append("No files detected in the monitored directory.")
    else:
        for filename in files:
            if filename in current_files:
                if filename not in baseline_data:
                    status = "NEW"
                    details = monitor.get_file_details(filename) if baseline_path.exists() else {"current_hash": ""}
                    hash_value = details.get("current_hash") or "N/A"
                else:
                    details = monitor.get_file_details(filename)
                    status = details.get("status", "UNKNOWN")
                    hash_value = details.get("current_hash") or details.get("original_hash") or "N/A"
            else:
                status = "DELETED"
                hash_value = "N/A"

            lines.append(f"- {filename}: {status} | SHA-256: {hash_value}")

    lines.extend(["", "Recent Audit Events", "-" * 20])
    if event_log:
        for entry in event_log[-20:]:
            timestamp, _, message = parse_audit_log_entry(entry)
            if message:
                lines.append(f"- {timestamp} | {message}")
    else:
        lines.append("No security events recorded yet.")

    return "\n".join(lines) + "\n"


class RealTimeMonitorHandler(FileSystemEventHandler):
    def __init__(self, callback, monitor_dir, baseline_path):
        super().__init__()
        self.callback = callback
        self.monitor_dir = Path(monitor_dir)
        self.baseline_path = Path(baseline_path)
        self._event_cache = {}

    def _event_key(self, event_type, file_name):
        return f"{event_type}:{file_name}"

    def on_created(self, event):
        if event.is_directory:
            return
        self._dispatch_event("created", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._dispatch_event("modified", event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._dispatch_event("deleted", event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self._dispatch_event("moved", event.dest_path)

    def _dispatch_event(self, event_type, path_value):
        event_path = Path(path_value)
        if not event_path.exists() and event_type != "deleted":
            return
        if event_path.name.startswith("."):
            return
        key = self._event_key(event_type, event_path.name)
        now = time.time()
        last_seen = self._event_cache.get(key)
        if last_seen and now - last_seen < 2.0:
            return
        self._event_cache[key] = now
        self.callback(event_type, event_path)


class FileIntegrityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Monitoring System")
        self.root.geometry("900x620")
        self.root.resizable(False, False)

        self.monitor = FileIntegrityMonitor("monitored_files", "baseline.json")
        self.event_log = []
        self.audit_log_path = Path("event_log.json")
        self.audit_status_var = None
        self._load_audit_log()
        self.monitoring_active = False
        self.real_time_monitoring_active = False
        self.monitor_interval = 3000
        self.monitor_job = None
        self.observer = None
        self.event_queue = queue.Queue()
        self.event_thread = None
        self.last_event_signature = None
        self.last_logged_events = set()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.bind("<Destroy>", self._on_root_destroy)
        self._build_ui()

    def _build_ui(self):
        title = tk.Label(self.root, text="File Integrity Monitoring System", font=("Arial", 18, "bold"))
        title.pack(pady=(16, 12))

        status_frame = ttk.LabelFrame(self.root, text="Security Status", padding=10)
        status_frame.pack(fill="x", padx=16, pady=(0, 8))

        self.status_var = tk.StringVar(value="SYSTEM SECURE")
        self.status_count_var = tk.StringVar(value="Detected Events: 0")

        ttk.Label(status_frame, textvariable=self.status_var, font=("Arial", 14, "bold"), foreground="#2e7d32").pack(anchor="w")
        ttk.Label(status_frame, textvariable=self.status_count_var, font=("Arial", 10)).pack(anchor="w")

        card_frame = ttk.Frame(self.root, padding=10)
        card_frame.pack(fill="x", padx=16)

        metrics = [
            ("Total Files", "total_files"),
            ("Safe", "safe_count"),
            ("Modified", "modified_count"),
            ("New", "new_count"),
            ("Deleted", "deleted_count"),
        ]

        self.metric_vars = {}
        for label_text, key in metrics:
            frame = ttk.Frame(card_frame)
            frame.pack(side="left", expand=True, fill="x", padx=6)
            ttk.Label(frame, text=label_text, font=("Arial", 10, "bold")).pack(anchor="w")
            var = tk.StringVar(value="0")
            ttk.Label(frame, textvariable=var, font=("Arial", 14, "bold"), foreground="#1f4e79").pack(anchor="w")
            self.metric_vars[key] = var

        button_frame = ttk.Frame(self.root, padding=(16, 8))
        button_frame.pack(fill="x", padx=16)

        ttk.Button(button_frame, text="Scan Now", command=self.run_scan).pack(side="left", padx=(0, 8))
        ttk.Button(button_frame, text="Create Baseline", command=self.create_baseline).pack(side="left", padx=8)
        ttk.Button(button_frame, text="View SHA-256 Hashes", command=self.show_hashes).pack(side="left", padx=8)
        ttk.Button(button_frame, text="VIEW DETAILS", command=self.view_details).pack(side="left", padx=8)
        ttk.Button(button_frame, text="ADD FILE", command=self.add_file).pack(side="left", padx=8)
        ttk.Button(button_frame, text="REMOVE FILE", command=self.remove_file).pack(side="left", padx=8)
        ttk.Button(button_frame, text="EXPORT REPORT", command=self.export_report).pack(side="left", padx=8)
        ttk.Button(button_frame, text="VERIFY AUDIT LOG", command=self.verify_audit_log).pack(side="left", padx=8)
        ttk.Button(button_frame, text="Security Event Log", command=self.show_log).pack(side="left", padx=8)

        monitor_control_frame = ttk.Frame(self.root, padding=(16, 0, 16, 10))
        monitor_control_frame.pack(fill="x")
        ttk.Button(monitor_control_frame, text="START MONITORING", command=self.start_monitoring).pack(side="left", padx=(0, 8))
        ttk.Button(monitor_control_frame, text="STOP MONITORING", command=self.stop_monitoring).pack(side="left", padx=8)
        ttk.Label(monitor_control_frame, text="Interval:").pack(side="left", padx=(8, 4))
        self.interval_var = tk.StringVar(value="3")
        interval_combo = ttk.Combobox(monitor_control_frame, textvariable=self.interval_var, width=8, state="readonly")
        interval_combo["values"] = ("1", "3", "5")
        interval_combo.pack(side="left")
        interval_combo.bind("<<ComboboxSelected>>", lambda event: self.set_interval())
        self.realtime_state_var = tk.StringVar(value="REAL-TIME MONITORING: STOPPED")
        self.audit_status_var = tk.StringVar(value="AUDIT LOG: VERIFIED")
        ttk.Label(monitor_control_frame, textvariable=self.realtime_state_var, font=("Arial", 10, "bold"), foreground="#c62828").pack(side="left", padx=(12, 0))
        ttk.Label(monitor_control_frame, textvariable=self.audit_status_var, font=("Arial", 10, "bold"), foreground="#1565c0").pack(side="left", padx=(12, 0))
        self._refresh_audit_status()

        detail_frame = ttk.LabelFrame(self.root, text="Scan Results", padding=10)
        detail_frame.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.tree = ttk.Treeview(detail_frame, columns=("file_name", "status", "hash"), show="headings", height=10)
        self.tree.heading("file_name", text="File Name")
        self.tree.heading("status", text="Status")
        self.tree.heading("hash", text="SHA-256 Hash")
        self.tree.column("file_name", width=220, anchor="w")
        self.tree.column("status", width=120, anchor="center")
        self.tree.column("hash", width=420, anchor="w")
        self.tree.pack(fill="both", expand=True)

        self.update_dashboard()

    def update_dashboard(self):
        self._apply_scan_result(self.monitor.check_integrity())

    def run_scan(self):
        return self._apply_scan_result(self.monitor.check_integrity())

    def _apply_scan_result(self, summary):
        self._update_metrics(summary)
        self._update_status_banner(summary)
        self._populate_treeview(summary)

        if summary["modified_count"] or summary["new_count"] or summary["deleted_count"]:
            self._record_security_events(summary)
            self._show_security_alert(summary)

        return summary

    def create_baseline(self):
        baseline_path = Path("baseline.json")
        create_baseline("monitored_files", baseline_path)
        self._add_event_log_entry("Baseline created")
        self.update_dashboard()
        messagebox.showinfo("Baseline", "Baseline created successfully.")

    def show_hashes(self):
        self.update_dashboard()

    def start_monitoring(self):
        if self.monitoring_active:
            return
        self.monitoring_active = True
        self.realtime_state_var.set("REAL-TIME MONITORING: ACTIVE")
        self._add_event_log_entry("Monitoring started")
        self._schedule_next_scan()
        self._start_realtime_monitoring()

    def stop_monitoring(self):
        if self.monitoring_active or self.monitor_job is not None or self.real_time_monitoring_active:
            self.monitoring_active = False
            self.real_time_monitoring_active = False
            self.realtime_state_var.set("REAL-TIME MONITORING: STOPPED")
            self._stop_realtime_monitoring()
            if self.monitor_job is not None:
                self.root.after_cancel(self.monitor_job)
                self.monitor_job = None
            self._add_event_log_entry("Monitoring stopped")

    def set_interval(self):
        try:
            self.monitor_interval = int(self.interval_var.get()) * 1000
        except ValueError:
            self.monitor_interval = 3000
        if self.monitoring_active:
            self.stop_monitoring()
            self.start_monitoring()

    def _schedule_next_scan(self):
        if not self.monitoring_active or self.root.winfo_exists() == 0:
            return
        if self.monitor_job is not None:
            self.root.after_cancel(self.monitor_job)
        self.monitor_job = self.root.after(self.monitor_interval, self._monitor_tick)

    def _monitor_tick(self):
        self.monitor_job = None
        if not self.monitoring_active or self.root.winfo_exists() == 0:
            return
        self._apply_scan_result(self.monitor.check_integrity())
        self._schedule_next_scan()

    def _record_security_events(self, summary):
        for change in summary["changes"]:
            change_type = str(change.get("type", "")).lower()
            file_name = str(change.get("file", ""))
            if change_type == "modified":
                event = f"MODIFIED: {file_name}"
            elif change_type == "new":
                event = f"NEW FILE: {file_name}"
            elif change_type == "deleted":
                event = f"DELETED: {file_name}"
            else:
                continue

            if event in self.last_logged_events:
                continue

            self.last_logged_events.add(event)
            self._add_event_log_entry(event)

    def _show_security_alert(self, summary):
        signature = tuple(sorted((f"{change['type']}:{change['file']}" for change in summary['changes'])))
        if self.last_event_signature == signature:
            return
        self.last_event_signature = signature
        messagebox.showwarning("Security Alert", "Integrity change detected.")

    def _add_event_log_entry(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.event_log.append(entry)
        self._save_audit_log(entry)

    def _refresh_audit_status(self):
        if not hasattr(self, "audit_status_var") or self.audit_status_var is None:
            return
        is_valid, _ = verify_event_log_integrity(self.audit_log_path)
        if is_valid:
            self.audit_status_var.set("AUDIT LOG: VERIFIED")
        else:
            self.audit_status_var.set("AUDIT LOG: TAMPERED")

    def _start_realtime_monitoring(self):
        if self.real_time_monitoring_active:
            return
        if self.observer is not None:
            self._stop_realtime_monitoring()
        self.monitor.monitor_dir.mkdir(parents=True, exist_ok=True)
        directory = str(self.monitor.monitor_dir)
        self.realtime_state_var.set("REAL-TIME MONITORING: ACTIVE")
        handler = RealTimeMonitorHandler(self._handle_realtime_event, directory, self.monitor.baseline_path)
        self.observer = Observer()
        self.observer.schedule(handler, directory, recursive=False)
        self.observer.start()
        self.real_time_monitoring_active = True
        self.event_thread = threading.Thread(target=self._drain_event_queue, daemon=True)
        self.event_thread.start()

    def _stop_realtime_monitoring(self):
        if self.observer is not None:
            self.observer.stop()
            self.observer.join(timeout=2)
            self.observer = None
        self.real_time_monitoring_active = False

    def _drain_event_queue(self):
        while self.real_time_monitoring_active:
            try:
                event_type, path_value = self.event_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            self.root.after(0, self._process_realtime_event, event_type, path_value)

    def _handle_realtime_event(self, event_type, path_value):
        self.event_queue.put((event_type, path_value))

    def _process_realtime_event(self, event_type, path_value):
        if not self.monitoring_active or self.root.winfo_exists() == 0:
            return
        path = Path(path_value)
        if not path.exists() and event_type != "deleted":
            return
        event = classify_realtime_event(event_type, path, self.monitor.monitor_dir, self.monitor.baseline_path)
        if event["classification"] == "SAFE":
            return
        message = build_realtime_event_message(event)
        self._add_event_log_entry(message)
        self._update_status_banner_from_event(event)
        self.update_dashboard()

    def _update_status_banner_from_event(self, event):
        classification = str(event.get("classification", "SAFE"))
        severity = str(event.get("severity", "LOW"))
        if classification == "SAFE":
            self.status_var.set("SYSTEM SECURE")
            self.status_count_var.set("Detected Events: 0")
        else:
            self.status_var.set(f"{classification} EVENT")
            self.status_count_var.set(f"Severity: {severity}")

    def _load_audit_log(self):
        if not self.audit_log_path.exists():
            self.audit_log_path.write_text("[]", encoding="utf-8")
            return

        try:
            with self.audit_log_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, list):
                self.event_log = []
                migrated_entries = migrate_event_log(self.audit_log_path)
                if migrated_entries:
                    self._persist_audit_log(migrated_entries)
                    data = migrated_entries
                for item in data:
                    if isinstance(item, dict):
                        timestamp = str(item.get("timestamp", ""))
                        message = str(item.get("message", ""))
                        if message:
                            self.event_log.append(f"[{timestamp}] {message}")
                    else:
                        timestamp, event_type, message = parse_audit_log_entry(item)
                        if message:
                            self.event_log.append(f"[{timestamp}] {message}")
            else:
                self.event_log = []
        except (json.JSONDecodeError, OSError):
            self.event_log = []
            messagebox.showwarning("Audit Log", "The audit log file is invalid or unreadable. Starting with an empty log.")

    def _save_audit_log(self, entry):
        try:
            with self.audit_log_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            data = []

        if not isinstance(data, list):
            data = []

        if isinstance(entry, str):
            timestamp, event_type, message = parse_audit_log_entry(entry)
            if not message:
                return
            if entry not in self.event_log:
                previous_hash = "GENESIS"
                if data:
                    previous_hash = str(data[-1].get("event_hash", "GENESIS"))
                event_hash = self._compute_event_hash(timestamp, event_type, message, previous_hash)
                data.append(
                    {
                        "timestamp": timestamp,
                        "event_type": event_type,
                        "message": message,
                        "previous_hash": previous_hash,
                        "event_hash": event_hash,
                    }
                )

        self._persist_audit_log(data)
        self._refresh_audit_status()

    def _persist_audit_log(self, data):
        with self.audit_log_path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=4)

    def _compute_event_hash(self, timestamp, event_type, message, previous_hash):
        from fim_engine import compute_event_hash

        return compute_event_hash(timestamp, event_type, message, previous_hash)

    @staticmethod
    def _event_type_from_message_static(message):
        if message.startswith("MODIFIED"):
            return "MODIFIED"
        if message.startswith("NEW FILE"):
            return "NEW"
        if message.startswith("DELETED"):
            return "DELETED"
        if message.startswith("Monitoring started"):
            return "MONITORING_STARTED"
        if message.startswith("Monitoring stopped"):
            return "MONITORING_STOPPED"
        if message.startswith("Baseline created"):
            return "BASELINE_CREATED"
        return "INFO"

    def _event_type_from_message(self, entry):
        _, _, message = parse_audit_log_entry(entry)
        return self._event_type_from_message_static(message)

    def export_report(self):
        summary = self.run_scan()
        is_valid, detail = verify_event_log_integrity(self.audit_log_path)
        audit_status = "VERIFIED" if is_valid else "TAMPERED"
        report_text = build_report_content(summary, self.monitor, self.event_log, audit_status)
        report_text += f"Audit Log Detail: {detail}\n"

        file_path = filedialog.asksaveasfilename(
            title="Save Security Report",
            initialfile="FileIntegrityReport.txt",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not file_path:
            return

        if not file_path.lower().endswith(".txt"):
            file_path = f"{file_path}.txt"

        try:
            Path(file_path).write_text(report_text, encoding="utf-8")
        except (OSError, PermissionError) as exc:
            messagebox.showerror("Export Failed", f"Unable to save the report.\n{exc}")
            return

        messagebox.showinfo("Report Exported", f"Security report saved successfully.\n\n{Path(file_path).name}")

    def show_log(self):
        if not self.event_log:
            self.event_log = []
            self.event_log.append("No security events recorded yet.")

        log_window = tk.Toplevel(self.root)
        log_window.title("Security Event Log")
        log_window.geometry("600x400")
        log_window.resizable(False, False)

        text_box = tk.Text(log_window, wrap="word")
        text_box.pack(fill="both", expand=True, padx=10, pady=(10, 0))
        text_box.insert("1.0", "\n".join(self.event_log))
        text_box.configure(state="disabled")

        button_frame = ttk.Frame(log_window, padding=10)
        button_frame.pack(fill="x")
        ttk.Button(button_frame, text="CLEAR EVENT LOG", command=self.clear_event_log).pack(anchor="e")

    def clear_event_log(self):
        confirmed = messagebox.askyesno("Clear Event Log", "Clear all stored security events?")
        if not confirmed:
            return

        self.event_log = []
        self.last_logged_events = set()
        self.audit_log_path.write_text("[]", encoding="utf-8")
        self._refresh_audit_status()
        messagebox.showinfo("Event Log", "Event history cleared.")

    def verify_audit_log(self):
        is_valid, detail = verify_event_log_integrity(self.audit_log_path)
        self._refresh_audit_status()
        if is_valid:
            messagebox.showinfo("AUDIT LOG VERIFIED", "No tampering detected.")
        else:
            messagebox.showwarning("AUDIT LOG TAMPERED", "The audit history may have been modified.")

    def view_details(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Selection Required", "Please select a file from the table first.")
            return

        file_name = self.tree.item(selected_item[0], "values")[0]
        details = self.monitor.get_file_details(file_name)

        details_window = tk.Toplevel(self.root)
        details_window.title("File Details")
        details_window.geometry("480x260")
        details_window.resizable(False, False)

        ttk.Label(details_window, text="File Integrity Details", font=("Arial", 14, "bold")).pack(pady=(12, 10))
        ttk.Label(details_window, text=f"File Name: {details['file_name']}", anchor="w").pack(fill="x", padx=16, pady=2)
        ttk.Label(details_window, text=f"Current Status: {details['status']}", anchor="w").pack(fill="x", padx=16, pady=2)
        ttk.Label(details_window, text=f"Original SHA-256: {details['original_hash'] or 'N/A'}", anchor="w", wraplength=430).pack(fill="x", padx=16, pady=2)
        ttk.Label(details_window, text=f"Current SHA-256: {details['current_hash'] or 'N/A'}", anchor="w", wraplength=430).pack(fill="x", padx=16, pady=2)

        result_var = tk.StringVar(value=details["comparison_result"])
        ttk.Label(details_window, textvariable=result_var, font=("Arial", 11, "bold"), foreground="#b71c1c").pack(fill="x", padx=16, pady=(8, 0))

    def add_file(self):
        file_path = filedialog.askopenfilename(title="Select a file to add")
        if not file_path:
            return

        source_path = Path(file_path)
        target_dir = self.monitor.monitor_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        target_path = target_dir / source_path.name

        if target_path.exists():
            confirm = messagebox.askyesno("Replace File", f"A file named {source_path.name} already exists. Replace it?")
            if not confirm:
                return

        try:
            shutil.copy2(source_path, target_path)
        except (OSError, PermissionError) as exc:
            messagebox.showerror("Copy Failed", f"Unable to copy the selected file.\n{exc}")
            return

        file_hash = calculate_hash(target_path)
        self._add_event_log_entry(f"NEW FILE: {source_path.name}")
        self.update_dashboard()
        messagebox.showinfo("File Added", f"File added successfully.\n\nFilename: {target_path.name}\nSHA-256: {file_hash}")

    def remove_file(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Selection Required", "Please select a file from the table first.")
            return

        file_name = self.tree.item(selected_item[0], "values")[0]
        confirm = messagebox.askyesno("Remove File", f"Remove '{file_name}' from the monitored folder?")
        if not confirm:
            return

        target_path = self.monitor.monitor_dir / file_name
        try:
            if target_path.exists():
                target_path.unlink()
        except (OSError, PermissionError) as exc:
            messagebox.showerror("Remove Failed", f"Unable to remove the selected file.\n{exc}")
            return

        self._add_event_log_entry(f"DELETED: {file_name}")
        self.update_dashboard()
        messagebox.showinfo("File Removed", f"Removed: {file_name}")

    def _update_metrics(self, summary):
        self.metric_vars["total_files"].set(str(summary["total_files"]))
        self.metric_vars["safe_count"].set(str(summary["safe_count"]))
        self.metric_vars["modified_count"].set(str(summary["modified_count"]))
        self.metric_vars["new_count"].set(str(summary["new_count"]))
        self.metric_vars["deleted_count"].set(str(summary["deleted_count"]))

    def _update_status_banner(self, summary):
        event_count = summary["modified_count"] + summary["new_count"] + summary["deleted_count"]
        if event_count == 0:
            self.status_var.set("SYSTEM SECURE")
            self.status_count_var.set(f"Detected Events: {event_count}")
        else:
            self.status_var.set("THREAT DETECTED")
            self.status_count_var.set(f"Detected Events: {event_count}")

    def on_close(self):
        if self.monitor_job is not None:
            self.root.after_cancel(self.monitor_job)
            self.monitor_job = None
        self.monitoring_active = False
        self.real_time_monitoring_active = False
        self._stop_realtime_monitoring()
        self.stop_monitoring()
        self.root.destroy()

    def _on_root_destroy(self, event=None):
        if self.monitor_job is not None:
            self.root.after_cancel(self.monitor_job)
            self.monitor_job = None
        self.monitoring_active = False
        self.real_time_monitoring_active = False
        self._stop_realtime_monitoring()

    def _populate_treeview(self, summary):
        for item in self.tree.get_children():
            self.tree.delete(item)

        monitor_dir = self.monitor.monitor_dir
        baseline_path = self.monitor.baseline_path

        current_files = {path.name for path in monitor_dir.iterdir() if path.is_file()} if monitor_dir.exists() else set()
        baseline_data = {}

        if baseline_path.exists():
            with baseline_path.open("r", encoding="utf-8") as handle:
                baseline_data = json.load(handle)

        all_files = sorted(set(current_files) | set(baseline_data.keys()))

        if not all_files:
            self.tree.insert("", "end", values=("No files found", "SAFE", "-"))
            return

        for filename in all_files:
            if filename in current_files:
                if filename not in baseline_data:
                    status = "NEW"
                    hash_value = calculate_hash(monitor_dir / filename)
                else:
                    current_hash = calculate_hash(monitor_dir / filename)
                    expected_hash = baseline_data[filename]
                    status = "SAFE" if current_hash == expected_hash else "MODIFIED"
                    hash_value = current_hash
            else:
                status = "DELETED"
                hash_value = "FILE NOT FOUND"

            self.tree.insert("", "end", values=(filename, status, hash_value))


def main():
    root = tk.Tk()
    app = FileIntegrityGUI(root)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        app.on_close()


if __name__ == "__main__":
    main()
