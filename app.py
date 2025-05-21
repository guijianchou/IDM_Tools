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
from typing import Generator # NoReturn removed, time removed


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
        raise # Errors should propagate to be handled by the caller or dispatcher


def scan_directory(temp_path: Path) -> Generator[Path, None, None]:
    """Lazily scan directory contents"""
    if not temp_path.exists():
        raise FileNotFoundError(f"Directory not found: {temp_path}")
    
    if not temp_path.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {temp_path}")

    yield from (entry for entry in temp_path.iterdir())


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

    try:
        resolved_path = Path(path_str).resolve() # Resolve the path string to a Path object
        
        if not resolved_path.exists():
            logging.error(f"Error: Path {resolved_path} does not exist.")
            return 1
        if not resolved_path.is_dir():
            logging.error(f"Error: Path {resolved_path} is not a directory.")
            return 1

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
    except FileNotFoundError as e:
        logging.error(f"Error: {str(e)}")
        return 1 # General error
    except NotADirectoryError as e:
        logging.error(f"Error: {str(e)}")
        return 1 # General error
    except Exception as e:
        logging.critical(f"Fatal error in clean_temp_files_main: {str(e)}", exc_info=True)
        return 1 # General error

# --- File Copying Functions (from copyfile.py) ---

def transfer_file(filename: str, root_dir: Path, dst_dir: Path) -> None:
    """Transfers a single file, then deletes original if successful."""
    src_path = root_dir / filename
    dst_path = dst_dir / filename
    
    try:
        shutil.copy2(src_path, dst_path)
        # Verify copy by size before deleting original
        if src_path.stat().st_size == dst_path.stat().st_size:
            src_path.unlink()
            logging.info(f"Successfully copied and removed: {src_path} to {dst_path}")
        else:
            logging.warning(f"Size mismatch for {filename} between {src_path} ({src_path.stat().st_size}B) and {dst_path} ({dst_path.stat().st_size}B). Original not deleted.")
    except FileNotFoundError:
        logging.error(f"Error processing {filename}: Source file {src_path} not found.")
        # Do not raise here to allow other files in batch to proceed
    except Exception as e:
        logging.error(f"Error processing {filename} from {src_path} to {dst_path}: {str(e)}")
        # Do not raise here to allow other files in batch to proceed

def copy_parallel(root_dir: Path, dst_dir: Path) -> None:
    """Copies files from root_dir to dst_dir in parallel and removes originals."""
    # List only files, not directories
    try:
        file_list = [f.name for f in root_dir.iterdir() if f.is_file()]
    except FileNotFoundError:
        logging.error(f"Source directory {root_dir} not found for copy_parallel.")
        raise # Re-raise because this is a fundamental issue for this function
    except NotADirectoryError:
        logging.error(f"Source path {root_dir} is not a directory for copy_parallel.")
        raise # Re-raise

    if not file_list:
        logging.info(f"No files found in {root_dir} to copy.")
        return

    # Use functools.partial to pass root_dir and dst_dir to transfer_file
    transfer_func = functools.partial(transfer_file, root_dir=root_dir, dst_dir=dst_dir)

    with ThreadPoolExecutor(max_workers=os.cpu_count() * 5) as executor: # Using a higher worker count like in original copyfile.py
        executor.map(transfer_func, file_list)


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

    try:
        root_dir = Path(root_dir_str).resolve()
        dst_dir = Path(dst_dir_str).resolve()

        if not root_dir.exists():
            logging.error(f"Source directory {root_dir} does not exist.")
            return 1
        if not root_dir.is_dir():
            logging.error(f"Source path {root_dir} is not a directory.")
            return 1

        # Create destination directory if it doesn't exist
        dst_dir.mkdir(parents=True, exist_ok=True)
        logging.info(f"Ensured destination directory exists: {dst_dir}")

        logging.info(f"Starting file copy from {root_dir} to {dst_dir}")
        copy_parallel(root_dir, dst_dir)
        logging.info(f"File copy operation completed from {root_dir} to {dst_dir}")
        return 0  # Success

    except FileNotFoundError as e: # Should be caught by copy_parallel or Path checks
        logging.error(f"File operation error in copy_files_main: {str(e)}")
        return 1
    except NotADirectoryError as e: # Should be caught by copy_parallel or Path checks
        logging.error(f"Path error in copy_files_main: {str(e)}")
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
        logging.error(f"Error reading {filepath} for hashing: {str(e)}")
        return None
    except Exception as e: # Catch other potential errors during file reading
        logging.error(f"Unexpected error reading {filepath} for hashing: {str(e)}")
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
        logging.error(f"Error getting metadata for {filepath}: {str(e)}")
        return None
    except Exception as e: # Catch other potential errors
        logging.error(f"Unexpected error getting metadata for {filepath}: {str(e)}")
        return None


def hash_files_main(input_dir_str: str) -> int:
    """
    Generates and updates a CSV file with file hashes and metadata for a directory.
    Returns an integer status code (0 for success, 1 for error).
    """
    try:
        input_dir = Path(input_dir_str).resolve()
        if not input_dir.is_dir():
            logging.error(f"Invalid directory path: {input_dir_str}")
            # raise ValueError("Invalid directory path") # Replaced with return code
            return 1
    except Exception as e: # Catch potential errors from Path() or resolve()
        logging.error(f"Error processing input directory path '{input_dir_str}': {str(e)}")
        return 1

    output_filename = "hash_results.csv"
    output_path = input_dir / output_filename
    existing_records = {} 

    if output_path.exists():
        try:
            with open(output_path, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        # Ensure 'filename' is present and construct full path for key
                        if 'filename' not in row:
                            logging.warning(f"Skipping record due to missing 'filename': {row}")
                            continue
                        
                        # Store relative path as key to match os.walk behavior
                        record_rel_path_str = row['filename'] # This is already a string
                        # Convert to float/int, ensure all keys exist
                        existing_records[record_rel_path_str] = { # Key is string rel_path
                            'filename': record_rel_path_str, # Value is also string rel_path
                            'md5': row.get('md5'),
                            'sha1': row.get('sha1'),
                            'sha256': row.get('sha256'),
                            'created': float(row['created']),
                            'modified': float(row['modified']),
                            'size': int(row['size'])
                        }
                    except (KeyError, ValueError) as e:
                        logging.warning(f"Skipping invalid record in {output_path}: {row} - {str(e)}")
                    except Exception as e: # Catch other unexpected errors
                        logging.error(f"Unexpected error processing row in {output_path}: {row} - {str(e)}")

        except (IOError, csv.Error) as e:
            logging.error(f"Error reading existing hash file {output_path}: {str(e)}")
            # Proceeding with empty existing_records, effectively treating it as a new run for safety
            existing_records = {}
        except Exception as e: # Catch other unexpected errors
            logging.error(f"Unexpected error reading {output_path}: {str(e)}")
            return 1

    initial_keys_from_csv = set(existing_records.keys())
    new_or_updated_records = [] # List of dicts for new/changed files
    processed_rel_paths = set() # Set of string relative paths found in current scan

    try:
        for root_str, _, files in os.walk(input_dir):
            root_path = Path(root_str)
            if root_path == output_path.parent and output_filename in files : # More robust check for output_path itself
                 # if root_path == input_dir and output_filename in files: # Simpler check if output is always in input_dir root
                pass # Allow processing if other files are in the same dir as output_path

            for filename_str in files:
                if root_path == input_dir and filename_str == output_filename:
                    continue # Skip the hash results file itself

                filepath = root_path / filename_str
                
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
                
                current_mtime = metadata['modified']
                existing_record = existing_records.get(rel_path_str)
                
                hashes_needed = True
                if existing_record and existing_record.get('modified') == current_mtime:
                    # File exists and modification time matches, assume hashes are current
                    # unless hash values are missing (e.g. from an old/incomplete CSV)
                    if existing_record.get('md5') and existing_record.get('sha1') and existing_record.get('sha256'):
                        hashes_needed = False
                
                if not hashes_needed:
                    # Add existing record to ensure it's kept in the output if no changes
                    # This is important if we rewrite the whole file or want to remove old entries
                    # For append mode, this might not be strictly needed if we only write new/changed
                    # However, the original script implies an update-in-place behavior for existing entries.
                    # For simplicity now, we will only add new/updated.
                    # If existing_record is to be preserved as is, it should be added to a 'current_run_records' list.
                    continue 

                hashes = get_hash(filepath)
                if not hashes:
                    logging.warning(f"Could not get hashes for {filepath}. Skipping.")
                    continue
                
                # Prepare the full record for this file
                current_file_record = {
                    'filename': rel_path_str,
                    **hashes,
                    **metadata # Ensure keys are 'size', 'created', 'modified'
                }

                # Check if it's truly new or if hashes changed
                if existing_record:
                    # Compare new hashes with existing ones if mtime differed or hashes were missing
                    hashes_changed = any(
                        current_file_record.get(alg) != existing_record.get(alg)
                        for alg in ('md5', 'sha1', 'sha256')
                    )
                    if not hashes_changed and not hashes_needed: # Redundant check if hashes_needed is false
                         continue # No change in mtime or hashes
                    # If mtime changed OR hashes changed, it's an update.
                    logging.info(f"Updating record for {rel_path_str} (mtime or hash changed).")
                else:
                    logging.info(f"Adding new record for {rel_path_str}.")
                
                new_or_updated_records.append(current_file_record) 
                # Update existing_records with the latest data (new or changed)
                # This ensures existing_records reflects the state of files processed in this run.
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
        # Records to write are those that correspond to files currently on disk (i.e., in processed_rel_paths)
        # and are stored with their latest data in existing_records.
        final_records_to_write = [existing_records[key] for key in sorted(list(processed_rel_paths)) if key in existing_records]
        # Sorting keys before list comprehension ensures sorted output if keys are iterated in order by writer.
        # Alternatively, sort final_records_to_write by 'filename' field before writing.
        final_records_to_write.sort(key=lambda r: r['filename'])


        fieldnames = ['filename', 'md5', 'sha1', 'sha256', 'size', 'created', 'modified']
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(final_records_to_write)
            logging.info(f"Hash CSV {output_path} updated. {len(new_or_updated_records)} files added/updated. {len(deleted_paths)} files removed. Total tracked: {len(final_records_to_write)}.")
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