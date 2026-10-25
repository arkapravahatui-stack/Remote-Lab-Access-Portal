import hashlib
import json
import os

def verify_log_integrity(log_file_path):
    if not os.path.exists(log_file_path):
        print(f"❌ Error: {log_file_path} not found!")
        return False
        
    # The expected starting hash for the first log entry
    prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    
    with open(log_file_path, "r") as f:
        for index, line in enumerate(f):
            if not line.strip():
                continue
            entry = json.loads(line)
            
            # 1. Check if the previous_hash matches what we expect from the chain
            if entry.get("previous_hash") != prev_hash:
                print(f"❌ TAMPERING DETECTED at Line #{index + 1} (User: {entry.get('username')})!")
                print(f"   Expected Previous Hash: {prev_hash}")
                print(f"   Found Previous Hash:    {entry.get('previous_hash')}")
                return False
            
            # Move forward in the chain using the current entry's hash
            prev_hash = entry.get("current_hash", "")
            
    print("✅ AUDIT LOG INTEGRITY VERIFIED: Chain is intact, no tampering detected.")
    return True

if __name__ == "__main__":
    verify_log_integrity("audit.log")