# Cell 1: Environment Setup

import os

# Folder we want to monitor
MONITOR_DIR = "monitored_files"

# Create the folder if it does not exist
if not os.path.exists(MONITOR_DIR):
    os.makedirs(MONITOR_DIR)

# Dummy system files
sample_files = {
    "config.sys": "VERSION=1.0.4\nALLOW_ACCESS=FALSE",
    "database.db": "USER_DATA_ENCRYPTED_BLOB",
    "app.exe": "BINARY_EXEC_MOCK_DATA"
}

# Create the files
for filename, content in sample_files.items():
    file_path = os.path.join(MONITOR_DIR, filename)

    with open(file_path, "w") as f:
        f.write(content)

print(f"Sandbox created successfully! 3 files generated inside: {MONITOR_DIR}")

# Cell 2: Generate SHA-256 Hashes

import hashlib

def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            data = f.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


print("\n--- File Hashes ---")

for filename in os.listdir(MONITOR_DIR):

    file_path = os.path.join(MONITOR_DIR, filename)

    if os.path.isfile(file_path):
        file_hash = calculate_hash(file_path)

        print(f"{filename}:")
        print(f"SHA-256: {file_hash}\n")

# Cell 3: Create Trusted Baseline

import json

BASELINE_FILE = "baseline.json"

baseline = {}

for filename in os.listdir(MONITOR_DIR):

    file_path = os.path.join(MONITOR_DIR, filename)

    if os.path.isfile(file_path):
        baseline[filename] = calculate_hash(file_path)

# Save the baseline
with open(BASELINE_FILE, "w") as f:
    json.dump(baseline, f, indent=4)

print("\n--- Trusted Baseline Created ---")

for filename, file_hash in baseline.items():
    print(f"{filename}: {file_hash}")

print(f"\nBaseline saved to: {BASELINE_FILE}")

# Cell 4: File Integrity Verification

print("\n--- Integrity Check ---")

# Load the trusted baseline
with open(BASELINE_FILE, "r") as f:
    saved_baseline = json.load(f)

changes_detected = False

# Check existing files
for filename, old_hash in saved_baseline.items():

    file_path = os.path.join(MONITOR_DIR, filename)

    # Check if the file was deleted
    if not os.path.exists(file_path):

        print(f"[DELETED] {filename}")
        changes_detected = True

    else:
        # Calculate current hash
        current_hash = calculate_hash(file_path)

        # Compare with original hash
        if current_hash != old_hash:

            print(f"[MODIFIED] {filename}")
            print(f"Original: {old_hash}")
            print(f"Current:  {current_hash}")

            changes_detected = True

        else:
            print(f"[OK] {filename} - No changes")

# Check for new files
for filename in os.listdir(MONITOR_DIR):

    if filename not in saved_baseline:

        print(f"[NEW FILE] {filename}")
        changes_detected = True

# Final result
if not changes_detected:

    print("\nSystem Integrity: SAFE")

else:

    print("\nSystem Integrity: WARNING - Changes Detected!")