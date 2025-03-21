#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

root_dir = Path("/mnt/c/Users/Zen/Downloads/")
dst_dir = Path("/mnt/e/Downloads")

def copy_parallel():
    file_list = [f for f in os.listdir(root_dir) if (root_dir / f).is_file()]
    
    with ThreadPoolExecutor(max_workers=os.cpu_count() * 5) as executor:
        executor.map(transfer_file, file_list)

def transfer_file(filename):
    src_path = root_dir / filename
    dst_path = dst_dir / filename
    
    try:
        shutil.copy2(src_path, dst_path)
        if src_path.stat().st_size == dst_path.stat().st_size:
            src_path.unlink()
            print(f"Processed: {filename}")
        else:
            print(f"Size mismatch: {filename}")
    except Exception as e:
        print(f"Error processing {filename}: {str(e)}")

if __name__ == '__main__':
    dst_dir.mkdir(parents=True, exist_ok=True)
    copy_parallel()
    print("Operation completed")