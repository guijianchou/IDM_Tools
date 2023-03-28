#!/usr/bin/env python
#-*-coding:utf-8-*-

__auther__='guijianchou'

'hash.py'

import os
import hashlib
import csv
import time

input_dir = input("Please input the directory path: ")
hash_results_path = os.path.join(input_dir, "hash_results.csv")

if not os.path.exists(input_dir):
    raise ValueError("The input directory does not exist!")

if os.path.exists(hash_results_path):
    with open(hash_results_path, mode="r") as f:
        hash_results = {row["filename"]: row for row in csv.DictReader(f)}
else:
    hash_results = {}

def hash_file(filename):
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    with open(filename, mode='rb') as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            h_md5.update(data)
            h_sha1.update(data)
            h_sha256.update(data)
    return {
        "filename": os.path.basename(filename),
        "md5": h_md5.hexdigest(),
        "sha1": h_sha1.hexdigest(),
        "sha256": h_sha256.hexdigest(),
        "size": os.path.getsize(filename),
        "created": time.ctime(os.path.getctime(filename)),
        "modified": time.ctime(os.path.getmtime(filename))
    }

new_results = []
for dirpath, dirnames, filenames in os.walk(input_dir):
    if "hash_results.csv" in filenames:
        continue
    for filename in filenames:
        if filename in hash_results:
            existing_result = hash_results[filename]
            filepath = os.path.join(dirpath, filename)
            new_modified = os.path.getmtime(filepath)
            if new_modified != float(existing_result["modified"]):
                new_result = hash_file(filepath)
                if new_result != existing_result:
                    new_results.append(new_result)
                    hash_results[filename] = new_result
        else:
            filepath = os.path.join(dirpath, filename)
            new_results.append(hash_file(filepath))
            hash_results[filename] = new_results[-1]

if new_results:
    with open(hash_results_path, mode="a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=new_results[0].keys())
        if not os.path.exists(hash_results_path):
            writer.writeheader()
        writer.writerows(new_results)
        print(f"Hashing completed! {len(new_results)} files added to {hash_results_path}")
else:
    print("No new files to hash.")
