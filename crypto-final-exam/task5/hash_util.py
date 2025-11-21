#!/usr/bin/env python3
import hashlib
import json
import sys
import os

def compute_hashes(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }

# Main logic
if len(sys.argv) != 2:
    print("Usage: python3 hash_util.py <filename>")
    sys.exit(1)

filename = sys.argv[1]
current_hashes = compute_hashes(filename)
json_file = "hashes.json"

if not os.path.exists(json_file):
    # First run → save original hashes
    with open(json_file, "w") as f:
        json.dump(current_hashes, f, indent=4)
    print("Original hashes saved to hashes.json")
    print(json.dumps(current_hashes, indent=4))
else:
    # Subsequent runs → compare
    with open(json_file) as f:
        saved_hashes = json.load(f)
    
    if current_hashes == saved_hashes:
        print("INTEGRITY CHECK: PASS")
    else:
        print("INTEGRITY CHECK: FAIL – FILE HAS BEEN TAMPERED!")
    
    print("Current hashes:")
    print(json.dumps(current_hashes, indent=4))
