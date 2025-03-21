#!/usr/bin/env python
#-*-coding;utf-8-*-

__auther__='guijianchou'

'clean_IDM.py'

import os
import shutil
filelist=[]
print("If your have different TEMP path, Please change your TEMP path : \n")
#filepath=input()
filepath="/mnt/e/Applications/Idm/Temps/DwnlData" #if you use the defult or self folder, Please Change the correct Path. for some reason, win cannot get os.uname(),some codes hard to change
filelist=os.listdir(filepath)
def __clean_file1():
    for x in filelist:
        print (x)
        m=os.path.join(filepath,x)
        print (m)
        try:
            shutil.rmtree(m)#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IDM Temporary Files Cleaner (v3.0)

Optimized with parallel processing and type safety
"""

from __future__ import annotations
__author__ = 'guijianchou'

import os
import shutil
import argparse
import logging
from typing import Generator, NoReturn
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def setup_logging(verbose: bool = False) -> None:
    """Configures logging with optional verbose mode"""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )


def batch_remove(targets: Generator[Path, None, None]) -> None:
    """Batch delete files/directories with thread pooling"""
    with ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
        for target in targets:
            executor.submit(safe_remove, target)


def safe_remove(target: Path) -> None:
    """Atomic removal with detailed error handling"""
    try:
        if target.is_symlink() or target.is_file():
            target.unlink(missing_ok=True)
            logging.debug(f"Removed file: {target}")
        elif target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
            logging.debug(f"Removed directory: {target}")
    except Exception as e:
        logging.error(f"Failed to remove {target}: {str(e)}")
        raise


def scan_directory(temp_path: Path) -> Generator[Path, None, None]:
    """Lazily scan directory contents"""
    if not temp_path.exists():
        raise FileNotFoundError(f"Directory not found: {temp_path}")
    
    if not temp_path.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {temp_path}")

    yield from (entry for entry in temp_path.iterdir())


def main() -> NoReturn:
    """CLI entry point with enhanced argument parsing"""
    parser = argparse.ArgumentParser(
        description="Optimized IDM Temp Cleaner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '-p', '--path',
        type=Path,
        default=Path('/mnt/e/Applications/Idm/Temps/DwnlData'),
        help="Target directory path"
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help="Simulate cleanup without actual deletion"
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Enable debug output"
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    try:
        targets = scan_directory(args.path.resolve())
        
        if args.dry_run:
            logging.warning("DRY RUN MODE - No files will be deleted")
            for target in targets:
                logging.info(f"[Dry Run] Would delete: {target}")
            exit(0)
            
        batch_remove(targets)
        logging.info(f"Cleaned {args.path} successfully")
        exit(0)
        
    except KeyboardInterrupt:
        logging.warning("Operation cancelled by user")
        exit(130)
    except Exception as e:
        logging.critical(f"Fatal error: {str(e)}")
        exit(1)


if __name__ == '__main__':
    main()
        except TypeError,e:
            print ('Exception:',e)
        finally:
            pass
    
def clean_file2():
    __clean_file1()  
    print ('already clean the \'IDM TEMPS\' !\n')

if __name__=='__main__':
    clean_file2()
    