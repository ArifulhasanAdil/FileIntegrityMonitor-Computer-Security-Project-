import argparse
import json
from pathlib import Path

from fim_engine import create_baseline, verify_integrity


def main() -> None:
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument("--monitor-dir", default="monitored_files", help="Directory to monitor")
    parser.add_argument("--baseline", default="baseline.json", help="Baseline file path")
    parser.add_argument("--create-baseline", action="store_true", help="Create a baseline snapshot")
    args = parser.parse_args()

    monitor_dir = Path(args.monitor_dir)
    baseline_path = Path(args.baseline)

    if args.create_baseline:
        create_baseline(monitor_dir, baseline_path)
        print(f"Baseline created at {baseline_path}")
        return

    report = verify_integrity(monitor_dir, baseline_path)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
