#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IDM Temporary Files Cleaner (v3.0)

Optimized with parallel processing and type safety
"""

from __future__ import annotations

__author__ = 'guijianchou' # Copied from cleanfile.py

# Standard library imports, sorted alphabetically
import argparse
import csv
import functools
import hashlib
import logging
import os
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Generator, Any, Callable, Dict, List, Set, Union # Optional removed


def setup_logging(verbose: bool = False) -> None:
    """Configures logging with optional verbose mode"""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )


# --- Helper Functions ---

def _resolve_and_validate_input_dir(path_str: str, dir_description: str) -> Path | None:
    """Resolves a path string and validates if it's an existing directory."""
    try:
        resolved_path = Path(path_str).resolve()
    except OSError as e:
        logging.error(f"Error resolving {dir_description.lower()} '{path_str}': {str(e)}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error resolving {dir_description.lower()} '{path_str}': {str(e)}", exc_info=True)
        return None

    if not resolved_path.is_dir(): # .is_dir() implies .exists()
        logging.error(f"{dir_description} '{resolved_path}' is not a valid directory or does not exist.")
        return None
    
    return resolved_path


# --- File Cleaning Functions ---

def batch_remove(targets: Generator[Path, None, None]) -> None:
    """Batch delete files/directories with thread pooling and error summarization."""
    futures = []
    with ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
        for target in targets:
            futures.append(executor.submit(safe_remove, target))
    
    failed_removals = 0
    for future in futures:
        try:
            # Attempt to get the result, which will re-raise any exception from safe_remove
            future.result() 
        except Exception as e: # Exception was already logged in safe_remove
            # The exception from safe_remove (already logged there) is caught here.
            # We just count failures for a summary.
            failed_removals += 1
            # Optionally, log a more specific error message here if needed,
            # but safe_remove already logs the details with exc_info=True.
            # logging.debug(f"A removal task failed (already logged): {e}")

    if failed_removals > 0:
        logging.warning(f"{failed_removals} target(s) could not be removed. See previous errors for details.")
    else:
        logging.info("All removal tasks completed successfully.")


def safe_remove(target: Path) -> None: # Keep None return type, exceptions signal failure
    """Atomic removal with detailed error handling"""
    try:
        if target.is_symlink() or target.is_file():
            target.unlink(missing_ok=True)
            logging.debug(f"Removed file: {target}")
        elif target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
            logging.debug(f"Removed directory: {target}")
    except Exception as e:
        logging.error(f"Failed to remove {target}: {str(e)}", exc_info=True)
        raise # Errors should propagate to be handled by the caller or dispatcher


def scan_directory(temp_path: Path) -> Generator[Path, None, None]:
    """Lazily scan directory contents"""
    if not temp_path.exists():
        raise FileNotFoundError(f"Directory not found: {temp_path}")
    
    if not temp_path.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {temp_path}")

    try:
        yield from (entry for entry in temp_path.iterdir())
    except FileNotFoundError: # Path disappeared between check and iterdir
        logging.error(f"Directory not found during iteration: {temp_path}")
        raise
    except NotADirectoryError: # Path changed type between check and iterdir
        logging.error(f"Path is not a directory during iteration: {temp_path}")
        raise
    except PermissionError: # Insufficient permissions to list directory
        logging.error(f"Permission denied to list directory: {temp_path}")
        raise


# Modified clean_temp_files_main to accept parameters directly
def clean_temp_files_main(path_str: str, dry_run: bool, verbose: bool) -> int:
    """
    Cleans temporary files from the specified path.
    Args:
        path_str: The directory path to clean.
        dry_run: If True, simulates cleanup without actual deletion.
        verbose: If True, enables verbose logging (already handled by global setup_logging).
    Returns:
        Status code (0 for success, 1 for error, 130 for KeyboardInterrupt).
    """
    # Logging is now set up globally by the dispatcher.
    # The 'verbose' parameter is primarily for the global logging setup;
    # its value is passed here for consistency but doesn't reconfigure logging.

    resolved_path = _resolve_and_validate_input_dir(path_str, "Path to clean")
    if not resolved_path:
        return 1

    try:
        targets = scan_directory(resolved_path)
        
        if dry_run:
            logging.warning("DRY RUN MODE - No files will be deleted")
            # Consume the generator to log all targets
            count = 0
            for target in targets:
                logging.info(f"[Dry Run] Would delete: {target}")
                count +=1
            if count == 0:
                logging.info(f"[Dry Run] No files found to delete in {resolved_path}")
            return 0 # Success
            
        batch_remove(targets) # targets is a generator, batch_remove will iterate over it
        logging.info(f"Successfully cleaned temporary files from {resolved_path}.")
        return 0 # Success
        
    except KeyboardInterrupt:
        logging.warning("Operation cancelled by user")
        return 130 # Standard exit code for SIGINT
    except FileNotFoundError as e: # From scan_directory or initial checks
        logging.error(f"File/Directory not found error: {str(e)}")
        return 1
    except NotADirectoryError as e: # From scan_directory or initial checks
        logging.error(f"Path is not a directory error: {str(e)}")
        return 1
    except PermissionError as e: # From scan_directory
        logging.error(f"Permission error: {str(e)}")
        return 1
    except Exception as e:
        logging.critical(f"Fatal error in clean_temp_files_main: {str(e)}", exc_info=True)
        return 1 # General error

# --- File Copying Functions (from copyfile.py) ---

def transfer_file(filename: str, root_dir: Path, dst_dir: Path) -> dict:
    """
    Transfers a single file, then deletes original if successful.
    Returns a dictionary with 'filepath', 'status' ('success', 'warning', 'error'), 
    and 'message'.
    """
    src_path = root_dir / filename
    dst_path = dst_dir / filename
    
    try:
        shutil.copy2(src_path, dst_path)
        logging.debug(f"Successfully copied {src_path} to {dst_path}")

        src_size = src_path.stat().st_size
        dst_size = dst_path.stat().st_size

        if src_size == dst_size:
            src_path.unlink()
            msg = f"Successfully transferred and verified {filename}: {src_path} to {dst_path}"
            logging.info(msg)
            return {"filepath": src_path, "status": "success", "message": msg}
        else:
            msg = (
                f"Size mismatch for {filename}: "
                f"{src_path} ({src_size}B) and {dst_path} ({dst_size}B). "
                "Original file not deleted."
            )
            logging.warning(msg)
            # This is a warning, but the file was copied. Original is kept.
            return {"filepath": src_path, "status": "warning", "message": msg}

    except FileNotFoundError:
        msg = f"Source file not found for {filename}: {src_path}"
        logging.error(msg)
        return {"filepath": src_path, "status": "error", "message": msg}
    
    except OSError as e:
        msg = f"OS error processing {filename} from {src_path} to {dst_path}: {str(e)}"
        logging.error(msg, exc_info=True)
        return {"filepath": src_path, "status": "error", "message": msg}
        
    except Exception as e:
        msg = f"Unexpected error processing {filename} from {src_path} to {dst_path}: {str(e)}"
        logging.error(msg, exc_info=True)
        return {"filepath": src_path, "status": "error", "message": msg}

def copy_parallel(root_dir: Path, dst_dir: Path) -> None:
    """
    Copies files from root_dir to dst_dir in parallel, removes originals if successful,
    and logs a summary of outcomes.
    """
    try:
        file_list = [f.name for f in root_dir.iterdir() if f.is_file()]
    except FileNotFoundError:
        logging.error(f"Source directory {root_dir} not found for copy_parallel. No files copied.")
        raise # This is a fundamental issue for this function, re-raise.
    except NotADirectoryError:
        logging.error(f"Source path {root_dir} is not a directory for copy_parallel. No files copied.")
        raise # Re-raise.
    except PermissionError:
        logging.error(f"Permission denied to list source directory {root_dir} for copy_parallel. No files copied.")
        raise # Re-raise.

    if not file_list:
        logging.info(f"No files found in {root_dir} to copy.")
        return

    transfer_func: Callable[[str], Dict[str, Any]] = functools.partial(transfer_file, root_dir=root_dir, dst_dir=dst_dir)

    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=os.cpu_count() * 5) as executor:
        # executor.map preserves order, which is nice but not strictly necessary here
        results = list(executor.map(transfer_func, file_list))

    succeeded_count: int = 0
    warning_count: int = 0
    failed_count: int = 0
    
    for res in results: # res is Dict[str, Any]
        if res["status"] == "success":
            succeeded_count += 1
        elif res["status"] == "warning":
            warning_count +=1
            # Warning message already logged by transfer_file
            logging.debug(f"Transfer warning for {res.get('filepath', 'N/A')}: {res.get('message', 'No message')}")
        elif res["status"] == "error":
            failed_count += 1
            # Error message already logged by transfer_file (with exc_info if applicable)
            logging.debug(f"Transfer error for {res.get('filepath', 'N/A')}: {res.get('message', 'No message')}")

    logging.info(
        f"Copy operation summary for {root_dir} to {dst_dir}: "
        f"{succeeded_count} file(s) succeeded, "
        f"{warning_count} file(s) with warnings (size mismatch, original not deleted), "
        f"{failed_count} file(s) failed."
    )
    if failed_count > 0 or warning_count > 0:
        logging.info("Review previous log messages for details on warnings and failures.")


def copy_files_main(root_dir_str: str, dst_dir_str: str) -> int:
    """
    Main function to copy files from a source directory to a destination directory.
    It creates the destination directory if it doesn't exist.
    Source and destination directories are provided as string paths.
    Returns an integer status code (0 for success, 1 for error).
    """
    # Logging setup should be handled by the dispatcher or calling context if this is part of a larger app.
    # For now, assume basic logging is configured (e.g. by clean_temp_files_main if called in same session, or a global setup).
    # If running standalone, setup_logging might be needed here.
    # setup_logging(verbose=True) # Example: if verbose is desired

    root_dir = _resolve_and_validate_input_dir(root_dir_str, "Source directory")
    if not root_dir:
        return 1

    try:
        # Resolve destination directory, but validation is different (it can be created)
        try:
            dst_dir = Path(dst_dir_str).resolve()
        except OSError as e:
            logging.error(f"Error resolving destination directory '{dst_dir_str}': {str(e)}")
            return 1
        except Exception as e:
            logging.error(f"Unexpected error resolving destination directory '{dst_dir_str}': {str(e)}", exc_info=True)
            return 1

        # Create destination directory if it doesn't exist
        try:
            dst_dir.mkdir(parents=True, exist_ok=True)
            logging.info(f"Ensured destination directory exists: {dst_dir}")
        except FileExistsError: # A file (not dir) exists at dst_dir path
            logging.error(f"Cannot create destination directory: A file already exists at {dst_dir}")
            return 1
        except PermissionError as e:
            logging.error(f"Permission denied to create destination directory {dst_dir}: {str(e)}")
            return 1
        except OSError as e: # Other OS-level errors during mkdir
            logging.error(f"OS error creating destination directory {dst_dir}: {str(e)}")
            return 1


        logging.info(f"Starting file copy from {root_dir} to {dst_dir}")
        copy_parallel(root_dir, dst_dir)
        logging.info(f"File copy operation completed from {root_dir} to {dst_dir}")
        return 0  # Success

    except FileNotFoundError as e: # From copy_parallel or initial checks on root_dir
        logging.error(f"File/Directory not found in copy operation: {str(e)}")
        return 1
    except NotADirectoryError as e: # From copy_parallel or initial checks on root_dir
        logging.error(f"Path is not a directory in copy operation: {str(e)}")
        return 1
    except PermissionError as e: # From copy_parallel
        logging.error(f"Permission error in copy operation: {str(e)}")
        return 1
    except Exception as e:
        logging.critical(f"Unexpected error in copy_files_main: {str(e)}", exc_info=True)
        return 1

# --- File Hashing Functions (from hashs.py) ---

def get_hash(filepath: Path, block_size: int = 65536) -> dict[str, str] | None:
    """
    Calculates MD5, SHA1, and SHA256 hashes for a file.

    Args:
        filepath: Path object representing the file to hash.
        block_size: Size of chunks to read from the file for hashing.
                    Defaults to 65536 bytes (64KB).

    Returns:
        A dictionary mapping hash algorithm names (e.g., 'md5', 'sha1', 'sha256')
        to their hexadecimal hash digests if successful, None otherwise.
    """
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(block_size):
                for alg_hash in hashes.values(): # Renamed 'alg' to 'alg_hash' to avoid conflict
                    alg_hash.update(chunk)
    except (IOError, PermissionError) as e:
        logging.error(f"Error reading {filepath} for hashing: {str(e)}") # No exc_info for specific (IOError, PermissionError)
        return None
    except Exception as e: # Catch other potential errors during file reading
        logging.error(f"Unexpected error reading {filepath} for hashing: {str(e)}", exc_info=True)
        return None
    
    return {alg_name: h.hexdigest() for alg_name, h in hashes.items()}


def get_file_metadata(filepath: Path) -> dict[str, float | int] | None:
    """
    Gets file metadata: size, creation time, and modification time.

    Args:
        filepath: Path object representing the file.

    Returns:
        A dictionary with 'size' (int), 'created' (float timestamp),
        and 'modified' (float timestamp) if successful, None otherwise.
    """
    try:
        return {
            'size': filepath.stat().st_size,
            'created': filepath.stat().st_ctime,
            'modified': filepath.stat().st_mtime
        }
    except OSError as e:
        logging.error(f"Error getting metadata for {filepath}: {str(e)}") # No exc_info for specific OSError
        return None
    except Exception as e: # Catch other potential errors
        logging.error(f"Unexpected error getting metadata for {filepath}: {str(e)}", exc_info=True)
        return None


def hash_files_main(input_dir_str: str) -> int:
    """
    Generates and updates a CSV file with file hashes and metadata for a directory.
    Returns an integer status code (0 for success, 1 for error).
    """
    input_dir = _resolve_and_validate_input_dir(input_dir_str, "Input directory")
    if not input_dir:
        return 1

    # Type alias for the structure of records in hash_files_main
    RecordValue = Union[str, float, int, None] # Allowing None for initially missing md5/sha1/sha256
    FileRecord = Dict[str, RecordValue]

    output_filename: str = "hash_results.csv"
    output_path: Path = input_dir / output_filename
    existing_records: Dict[str, FileRecord] = {} 

    try:
        with open(output_path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    if 'filename' not in row:
                        logging.warning(f"Skipping record due to missing 'filename' in {output_path}: {row}")
                        continue
                    
                    record_rel_path_str: str = row['filename']
                    # Ensure all expected fields are present, converting types carefully
                    try:
                        record: FileRecord = {
                            'filename': record_rel_path_str,
                            'md5': row.get('md5'), # Can be None if not in CSV
                            'sha1': row.get('sha1'), # Can be None
                            'sha256': row.get('sha256'), # Can be None
                            'created': float(row['created']),
                            'modified': float(row['modified']),
                            'size': int(row['size'])
                        }
                        existing_records[record_rel_path_str] = record
                    except (KeyError, ValueError) as e: # Catch if 'created', 'modified', 'size' are missing or not convertible
                        logging.warning(f"Skipping invalid or incomplete record in {output_path} for '{record_rel_path_str}': {row} - Error: {str(e)}")
                except (KeyError, ValueError) as e: # Catch outer errors, e.g. if 'filename' itself causes an issue before constructing the record
                    logging.warning(f"Skipping invalid record in {output_path}: {row} - Error: {str(e)}")
                except Exception as e:
                    logging.error(f"Unexpected error processing a row in {output_path}: {row} - Error: {str(e)}", exc_info=True)
    except FileNotFoundError:
        logging.info(f"Hash file {output_path} not found. A new one will be created.")
        existing_records = {} # Ensure it's empty if file not found
    except PermissionError as e:
        logging.error(f"Permission denied reading hash file {output_path}: {str(e)}")
        return 1 # Cannot proceed without knowing previous state or being able to update
    except IsADirectoryError as e:
        logging.error(f"Cannot read hash file: {output_path} is a directory: {str(e)}")
        return 1
    except (IOError, csv.Error) as e: # Covers other file reading issues or CSV format problems
        logging.error(f"Error reading or parsing hash file {output_path}: {str(e)}. Treating as empty.") # Specific error type, str(e) is enough
        existing_records = {} # Treat as empty and try to rebuild
    except Exception as e:
        logging.error(f"Unexpected error opening or reading {output_path}: {str(e)}", exc_info=True)
        return 1 # More critical failure

    initial_keys_from_csv: Set[str] = set(existing_records.keys())
    # new_or_updated_records will store FileRecord dictionaries
    new_or_updated_records: List[FileRecord] = [] 
    processed_rel_paths: Set[str] = set()

    try:
        for root_str, _, files_in_dir in os.walk(input_dir): # Renamed files to files_in_dir
            root_path = Path(root_str)
            # More robust check for output_path itself, avoid processing if it's the only thing
            # This condition is tricky; os.walk yields dirpath, dirnames, filenames.
            # We want to skip the output_path if it's listed as a file in its own parent directory.
            # The current logic is: if root_path is input_dir and output_filename is in files_in_dir, skip it.

            for filename_str in files_in_dir:
                if root_path == input_dir and filename_str == output_filename:
                    continue # Skip the hash results file itself

                filepath: Path = root_path / filename_str
                
                # Use relative path for dictionary keys and CSV storage
                try:
                    rel_path_str = str(filepath.relative_to(input_dir))
                except ValueError: # Should not happen if os.walk starts from input_dir
                    logging.warning(f"Could not determine relative path for {filepath} against {input_dir}. Skipping.")
                    continue
                
                processed_rel_paths.add(rel_path_str)
                metadata = get_file_metadata(filepath)
                if not metadata:
                    logging.warning(f"Could not get metadata for {filepath}. Skipping.")
                    continue
                
                current_mtime: float = metadata['modified'] # metadata is dict[str, float | int]
                existing_record: FileRecord | None = existing_records.get(rel_path_str)
                
                hashes_needed: bool = True
                if existing_record and existing_record.get('modified') == current_mtime:
                    if existing_record.get('md5') and existing_record.get('sha1') and existing_record.get('sha256'):
                        hashes_needed = False
                
                if not hashes_needed:
                    # If hashes are not needed, and we are not rewriting the whole CSV / removing old entries,
                    # we might skip. However, to ensure deleted files are removed from CSV,
                    # we need to build a list of all *current* files.
                    # The current logic correctly continues if hashes are not needed,
                    # but relies on `existing_records` being updated later if it *was* needed.
                    # This seems fine as `processed_rel_paths` tracks all files seen.
                    # If the record is to be kept as is, it's already in existing_records.
                    # If we were to optimize by not re-adding, it would be more complex.
                    # The current approach will re-add it to `new_or_updated_records` if mtime changed or hashes were missing.
                    pass # Let it proceed to hash calculation if needed or record update

                current_hashes: dict[str, str] | None = None
                if hashes_needed:
                    current_hashes = get_hash(filepath)
                    if not current_hashes:
                        logging.warning(f"Could not get hashes for {filepath}. Skipping.")
                        continue
                
                # Prepare the full record for this file
                # Ensure metadata keys are correctly typed when creating current_file_record
                current_file_record: FileRecord = {
                    'filename': rel_path_str,
                    'md5': current_hashes.get('md5') if current_hashes else (existing_record.get('md5') if existing_record else None),
                    'sha1': current_hashes.get('sha1') if current_hashes else (existing_record.get('sha1') if existing_record else None),
                    'sha256': current_hashes.get('sha256') if current_hashes else (existing_record.get('sha256') if existing_record else None),
                    'size': int(metadata['size']), # Ensure int
                    'created': float(metadata['created']), # Ensure float
                    'modified': float(metadata['modified']) # Ensure float
                }

                is_new_or_changed_record = False
                if existing_record:
                    if hashes_needed: # Implies mtime changed or hashes were missing
                        is_new_or_changed_record = True
                        logging.info(f"Updating record for {rel_path_str} (mtime or hash changed).")
                    # If not hashes_needed, it means mtime matched and all hashes were present.
                    # In this case, the record is not considered "new or updated" for the purpose of `new_or_updated_records` list.
                    # It will be part of `final_records_to_write` via `existing_records` if `processed_rel_paths` includes it.
                else:
                    is_new_or_changed_record = True
                    logging.info(f"Adding new record for {rel_path_str}.")
                
                if is_new_or_changed_record:
                    new_or_updated_records.append(current_file_record)
                else:
                    logging.info(f"Adding new record for {rel_path_str}.")
                
                new_or_updated_records.append(current_file_record) 
                # Always update existing_records to reflect the most current data for this file
                existing_records[rel_path_str] = current_file_record

    except Exception as e:
        logging.error(f"Error during file walk and processing in {input_dir}: {str(e)}", exc_info=True)
        return 1
        
    deleted_paths = initial_keys_from_csv - processed_rel_paths
    if deleted_paths:
        for deleted_path in deleted_paths:
            logging.info(f"File {deleted_path} was in CSV but not found in scan; will be removed.")
            if deleted_path in existing_records: # Remove from our working copy
                del existing_records[deleted_path]

    # Condition for writing: if new files added, existing files updated, or files were deleted.
    if new_or_updated_records or deleted_paths:
        # Rebuild final_records_to_write from the updated existing_records, considering only processed_rel_paths
        final_records_to_write: List[FileRecord] = []
        for rel_path_key in sorted(list(processed_rel_paths)):
            if rel_path_key in existing_records:
                final_records_to_write.append(existing_records[rel_path_key])
        # Sorting by 'filename' field before writing (already sorted by key, but good for explicit clarity if keys weren't sorted)
        # final_records_to_write.sort(key=lambda r: r['filename']) # Keys are already sorted

        fieldnames: List[str] = ['filename', 'md5', 'sha1', 'sha256', 'size', 'created', 'modified']
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                # Writer expects row values to be str, but our FileRecord has mixed types (str, float, int, None).
                # csv.DictWriter handles string conversion for basic types (int, float)
                # and writes None as an empty string. This behavior is acceptable.
                writer.writeheader()
                writer.writerows(final_records_to_write)
            logging.info(f"Hash CSV {output_path} updated. {len(new_or_updated_records)} files added/updated. {len(deleted_paths)} files removed. Total tracked: {len(final_records_to_write)}.")
        except PermissionError as e:
            logging.error(f"Permission denied writing hash CSV to {output_path}: {str(e)}")
            return 1
        except IsADirectoryError as e:
            logging.error(f"Cannot write hash CSV: {output_path} is a directory: {str(e)}")
            return 1
        except (IOError, csv.Error) as e:
            logging.error(f"Error writing hash CSV {output_path}: {str(e)}")
            return 1
        except Exception as e:
            logging.error(f"Unexpected error writing {output_path}: {str(e)}", exc_info=True)
            return 1
    else:
        logging.info(f"No changes detected in {input_dir}. Hash CSV not modified.")

    return 0 # Success


if __name__ == '__main__':
    main_parser = argparse.ArgumentParser(description="File Operations Utility")
    main_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Enable verbose logging for all operations."
    )
    
    subparsers = main_parser.add_subparsers(dest='command', required=True, help="Available commands")

    # --- Clean command ---
    clean_parser = subparsers.add_parser('clean', help="Clean temporary files from a directory.")
    clean_parser.add_argument(
        '--path',
        type=str, # Keep as string, Path conversion is in clean_temp_files_main
        required=True,
        help="Directory path to clean."
    )
    clean_parser.add_argument(
        '--dry-run',
        action='store_true',
        help="Simulate cleanup without actual deletion."
    )
    # The verbose flag for clean_parser is covered by the main_parser's verbose flag.
    # If specific verbosity per command was needed, it could be added here too.

    # --- Copy command ---
    copy_parser = subparsers.add_parser('copy', help="Copy files from source to destination and remove originals.")
    copy_parser.add_argument(
        '--source',
        type=str, # Keep as string for consistency
        required=True,
        help="Source directory path."
    )
    copy_parser.add_argument(
        '--destination',
        type=str, # Keep as string
        required=True,
        help="Destination directory path."
    )

    # --- Hash command ---
    hash_parser = subparsers.add_parser('hash', help="Generate and update a CSV of file hashes in a directory.")
    hash_parser.add_argument(
        '--path',
        type=str, # Keep as string
        required=True,
        help="Directory path to hash."
    )

    args = main_parser.parse_args()

    # Setup logging based on the global verbose flag
    # This should be done once, after parsing args.
    setup_logging(args.verbose) # Global verbose setting

    status_code = 1 # Default error status

    try:
        if args.command == 'clean':
            # Pass the global verbose setting to clean_temp_files_main, though it might not use it directly for logging setup anymore
            status_code = clean_temp_files_main(path_str=args.path, dry_run=args.dry_run, verbose=args.verbose)
        elif args.command == 'copy':
            status_code = copy_files_main(root_dir_str=args.source, dst_dir_str=args.destination)
        elif args.command == 'hash':
            status_code = hash_files_main(input_dir_str=args.path)
        else:
            # Should not happen due to `required=True` in add_subparsers, but as a fallback:
            logging.error(f"Unknown command: {args.command}")
            main_parser.print_help()
            status_code = 1
            
    except KeyboardInterrupt:
        logging.warning("Operation cancelled by user (main dispatcher).")
        status_code = 130 # Standard exit code for SIGINT
    except Exception as e:
        # Catch-all for unexpected errors in the dispatcher or if _main functions raise something unexpected
        logging.critical(f"Critical error in dispatcher: {str(e)}", exc_info=True)
        status_code = 1
        
    sys.exit(status_code)
