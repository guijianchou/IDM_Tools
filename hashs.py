#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'guijianchou'
__version__ = '1.1'

import os
import hashlib
import csv
import time

def get_hash(filepath, block_size=65536):
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(block_size):
                for alg in hashes.values():
                    alg.update(chunk)
    except (IOError, PermissionError) as e:
        print(f"Error reading {filepath}: {str(e)}")
        return None
    
    return {alg: h.hexdigest() for alg, h in hashes.items()}

def get_file_metadata(filepath):
    try:
        return {
            'size': os.path.getsize(filepath),
            'created': os.path.getctime(filepath),
            'modified': os.path.getmtime(filepath)
        }
    except OSError as e:
        print(f"Error getting metadata for {filepath}: {str(e)}")
        return None

def main():
    input_dir = input("Please input the directory path: ").strip()
    if not os.path.isdir(input_dir):
        raise ValueError("Invalid directory path")
    
    output_path = os.path.join(input_dir, "hash_results.csv")
    existing = {}
    
    if os.path.exists(output_path):
        with open(output_path, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    key = os.path.relpath(row['filename'], input_dir)
                    row['created'] = float(row['created'])
                    row['modified'] = float(row['modified'])
                    row['size'] = int(row['size'])
                    existing[key] = row
                except (KeyError, ValueError) as e:
                    print(f"Skipping invalid record: {row} - {str(e)}")
    
    new_records = []
    
    for root, _, files in os.walk(input_dir):
        if os.path.basename(root) == output_path:
            continue
        
        for filename in files:
            if filename == "hash_results.csv":
                continue
            
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, input_dir)
            
            metadata = get_file_metadata(filepath)
            if not metadata:
                continue
            
            current_mtime = metadata['modified']
            existing_record = existing.get(rel_path)
            
            if existing_record and existing_record['modified'] == current_mtime:
                continue
            
            hashes = get_hash(filepath)
            if not hashes:
                continue
            
            new_record = {
                'filename': rel_path,
                ​**hashes,
                ​**metadata
            }
            
            if existing_record:
                changed = any(
                    new_record[alg] != existing_record[alg]
                    for alg in ('md5', 'sha1', 'sha256')
                )
                if not changed:
                    continue
            
            new_records.append(new_record)
            existing[rel_path] = new_record
    
    if new_records:
        fieldnames = ['filename', 'md5', 'sha1', 'sha256', 'size', 'created', 'modified']
        write_header = not os.path.exists(output_path)
        
        with open(output_path, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if write_header:
                writer.writeheader()
            writer.writerows(new_records)
        
        print(f"Updated {len(new_records)} records. Total tracked files: {len(existing)}")
    else:
        print("No changes detected.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"Critical error: {str(e)}")