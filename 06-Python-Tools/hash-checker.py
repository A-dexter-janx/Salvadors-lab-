#!/usr/bin/env python3
"""
Hash Checker - File Integrity Verification Tool
Computes and verifies file hashes (MD5, SHA1, SHA256, SHA512).

Usage:
    python3 hash-checker.py <file>
    python3 hash-checker.py file.exe --algorithm sha256
    python3 hash-checker.py file.txt --verify known-hashes.txt

Author: Salvador Janthan
"""

import argparse
import hashlib
import sys
from pathlib import Path

__version__ = "1.0.0"

SUPPORTED_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

def compute_hash(filepath, algorithm="sha256", chunk_size=8192):
    """Compute hash of a file"""
    hasher = SUPPORTED_ALGORITHMS.get(algorithm.lower(), hashlib.sha256)()
    
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied for '{filepath}'", file=sys.stderr)
        sys.exit(1)
    
    return hasher.hexdigest()

def parse_known_hashes(filepath):
    """Parse a file with known hashes (format: hash  filename)"""
    hashes = {}
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) >= 2:
                    hash_val, filename = parts[0], parts[1]
                    hashes[filename.lower()] = hash_val
    except FileNotFoundError:
        print(f"Error: Hash file '{filepath}' not found", file=sys.stderr)
        sys.exit(1)
    return hashes

def verify_hash(filepath, known_hashes_file, algorithm="sha256"):
    """Verify file against known hashes"""
    computed = compute_hash(filepath, algorithm)
    known = parse_known_hashes(known_hashes_file)
    
    filename_lower = Path(filepath).name.lower()
    
    if filename_lower in known:
        expected = known[filename_lower]
        match = computed.lower() == expected.lower()
        status = "MATCH" if match else "MISMATCH"
        print(f"File: {filepath}")
        print(f"Algorithm: {algorithm.upper()}")
        print(f"Computed:  {computed}")
        print(f"Expected:  {expected}")
        print(f"Status:    {status}")
        return match
    else:
        print(f"Warning: '{filepath}' not found in {known_hashes_file}")
        print(f"Computed hash: {computed}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description="File Hash Checker - Compute and verify file integrity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 hash-checker.py malware.exe
  python3 hash-checker.py document.pdf --algorithm sha256
  python3 hash-checker.py file.iso --verify hashes.txt
        """
    )
    parser.add_argument("file", help="File to hash or verify")
    parser.add_argument("-a", "--algorithm", default="sha256",
                        choices=list(SUPPORTED_ALGORITHMS.keys()),
                        help="Hash algorithm (default: sha256)")
    parser.add_argument("-v", "--verify", metavar="FILE",
                        help="Verify against known hashes file")
    parser.add_argument("--all", action="store_true",
                        help="Compute all supported hashes")
    parser.add_argument("--version", action="version",
                        version=f"hash-checker.py {__version__} — File Hash Checker")

    args = parser.parse_args()
    
    if args.verify:
        result = verify_hash(args.file, args.verify, args.algorithm)
        sys.exit(0 if result is None or result else 1)
    elif args.all:
        print(f"File: {args.file}")
        print("-" * 40)
        for algo in SUPPORTED_ALGORITHMS:
            hash_val = compute_hash(args.file, algo)
            print(f"{algo.upper():8}: {hash_val}")
    else:
        hash_val = compute_hash(args.file, args.algorithm)
        print(f"Algorithm: {args.algorithm.upper()}")
        print(f"File: {args.file}")
        print(f"Hash: {hash_val}")

if __name__ == "__main__":
    main()
