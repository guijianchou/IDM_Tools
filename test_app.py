import unittest
from unittest import mock
from pathlib import Path
import tempfile
import shutil
import hashlib
import os # For os.stat and other os level operations if needed

# Assuming app.py is in the same directory or accessible via PYTHONPATH
import app

class TestResolveAndValidateInputDir(unittest.TestCase):
    @mock.patch('app.Path', autospec=True)
    def test_valid_directory(self, mock_Path_class):
        # Configure the instance returned by Path(path_str)
        mock_instance = mock_Path_class.return_value 
        mock_instance.resolve.return_value = mock_instance # resolve() returns the same mock instance
        mock_instance.is_dir.return_value = True
        
        path_str = "/valid/dir"
        result = app._resolve_and_validate_input_dir(path_str, "Test Dir")
        
        self.assertEqual(result, mock_instance)
        mock_Path_class.assert_called_with(path_str) # Path(path_str)
        mock_instance.resolve.assert_called_once()    # .resolve()
        mock_instance.is_dir.assert_called_once()     # .is_dir()

    @mock.patch('app.Path', autospec=True)
    def test_non_existent_path(self, mock_Path_class):
        mock_instance = mock_Path_class.return_value
        mock_instance.resolve.return_value = mock_instance
        # is_dir() will return False if path doesn't exist or is not a dir.
        # The function's logic relies on is_dir() to cover non-existence after successful resolution.
        mock_instance.is_dir.return_value = False 
        
        result = app._resolve_and_validate_input_dir("/non/existent", "Test Dir")
        self.assertIsNone(result)
        mock_instance.is_dir.assert_called_once()

    @mock.patch('app.Path', autospec=True)
    def test_path_is_file(self, mock_Path_class):
        mock_instance = mock_Path_class.return_value
        mock_instance.resolve.return_value = mock_instance
        mock_instance.is_dir.return_value = False # Key for a file
        
        result = app._resolve_and_validate_input_dir("/path/to/file", "Test Dir")
        self.assertIsNone(result)
        mock_instance.is_dir.assert_called_once()

    @mock.patch('app.Path', autospec=True)
    def test_resolve_os_error(self, mock_Path_class):
        mock_instance = mock_Path_class.return_value
        mock_instance.resolve.side_effect = OSError("Resolution failed")
        
        result = app._resolve_and_validate_input_dir("/path/to/file", "Test Dir")
        self.assertIsNone(result)
        # is_dir should not be called if resolve fails
        mock_instance.is_dir.assert_not_called()

class TestSafeRemove(unittest.TestCase):
    def setUp(self):
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.temp_dir = Path(self.temp_dir_obj.name)
        self.test_file = self.temp_dir / "test_file.txt"
        self.test_file.write_text("test")
        
        self.test_subdir = self.temp_dir / "test_subdir"
        self.test_subdir.mkdir()

    def tearDown(self):
        self.temp_dir_obj.cleanup()

    def test_remove_file_real(self):
        app.safe_remove(self.test_file)
        self.assertFalse(self.test_file.exists())

    def test_remove_directory_real(self):
        app.safe_remove(self.test_subdir)
        self.assertFalse(self.test_subdir.exists())

    @mock.patch('app.shutil.rmtree')
    @mock.patch('app.Path.unlink') # Mocking app.Path.unlink assumes Path objects used in app.py are MagicMocks or similar
    def test_remove_file_calls_unlink(self, mock_unlink, mock_rmtree):
        # Create a MagicMock for the Path object that will be passed to safe_remove
        mock_target_path = mock.MagicMock(spec=Path)
        mock_target_path.is_symlink.return_value = False
        mock_target_path.is_file.return_value = True
        mock_target_path.is_dir.return_value = False
        
        # To use mock_unlink for the method call on mock_target_path,
        # mock_target_path.unlink needs to BE mock_unlink.
        mock_target_path.unlink = mock_unlink 

        app.safe_remove(mock_target_path)
        
        mock_unlink.assert_called_once_with(missing_ok=True)
        mock_rmtree.assert_not_called()

    @mock.patch('app.shutil.rmtree')
    @mock.patch('app.Path.unlink')
    def test_remove_directory_calls_rmtree(self, mock_unlink, mock_rmtree):
        mock_target_path = mock.MagicMock(spec=Path)
        mock_target_path.is_symlink.return_value = False
        mock_target_path.is_file.return_value = False
        mock_target_path.is_dir.return_value = True
        # shutil.rmtree is called with the Path object itself.
        
        app.safe_remove(mock_target_path)
        
        mock_rmtree.assert_called_once_with(mock_target_path, ignore_errors=True)
        mock_target_path.unlink.assert_not_called() # Path.unlink is a method of Path, not a free function

    @mock.patch('app.logging.error')
    def test_remove_file_permission_error_raises(self, mock_logging_error):
        mock_target_path = mock.MagicMock(spec=Path)
        mock_target_path.is_symlink.return_value = False
        mock_target_path.is_file.return_value = True
        mock_target_path.is_dir.return_value = False
        mock_target_path.unlink.side_effect = OSError("Permission denied")
        # To make the error message in app.py meaningful with a mock
        mock_target_path.__str__ = mock.Mock(return_value="mock/file/path.txt")


        with self.assertRaises(OSError):
            app.safe_remove(mock_target_path)
        
        mock_logging_error.assert_called_once()
        args, kwargs = mock_logging_error.call_args
        self.assertIn("Failed to remove mock/file/path.txt: Permission denied", args[0])
        self.assertTrue(kwargs.get('exc_info'))


class TestTransferFile(unittest.TestCase):
    def setUp(self):
        self.source_temp_dir_obj = tempfile.TemporaryDirectory(prefix="transfer_source_")
        self.dest_temp_dir_obj = tempfile.TemporaryDirectory(prefix="transfer_dest_")
        self.root_dir = Path(self.source_temp_dir_obj.name)
        self.dst_dir = Path(self.dest_temp_dir_obj.name)
        self.filename = "test_transfer.txt"
        self.src_file_path = self.root_dir / self.filename
        self.src_file_path.write_text("This is content for transfer.")

    def tearDown(self):
        self.source_temp_dir_obj.cleanup()
        self.dest_temp_dir_obj.cleanup()

    def test_successful_transfer(self):
        result = app.transfer_file(self.filename, self.root_dir, self.dst_dir)
        
        dest_file_path = self.dst_dir / self.filename
        self.assertTrue(dest_file_path.exists())
        self.assertEqual(dest_file_path.read_text(), "This is content for transfer.")
        self.assertFalse(self.src_file_path.exists()) # Source deleted
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["filepath"], self.src_file_path) # Check if Path object is returned

    @mock.patch('app.Path.stat') # Mock Path.stat globally for this test
    def test_size_mismatch(self, mock_stat_method):
        # Let the actual file copy happen first
        shutil.copy2(self.src_file_path, self.dst_dir / self.filename)
        
        def selective_stat_side_effect(path_instance_being_statted):
            mock_stat_result = mock.MagicMock()
            # Compare the string representation
            if str(path_instance_being_statted) == str(self.root_dir / self.filename): # src_path
                mock_stat_result.st_size = 100
            elif str(path_instance_being_statted) == str(self.dst_dir / self.filename): # dst_path
                mock_stat_result.st_size = 50 
            else:
                # Fallback to real os.stat for any other path if necessary,
                # but for this test, we only care about these two.
                # Raise an error if an unexpected path's stat is being called and relied upon.
                raise AssertionError(f"Unexpected path statted: {path_instance_being_statted}")
            return mock_stat_result

        mock_stat_method.side_effect = selective_stat_side_effect
        
        result = app.transfer_file(self.filename, self.root_dir, self.dst_dir)
        
        self.assertTrue(self.src_file_path.exists()) # Source NOT deleted
        self.assertEqual(result["status"], "warning")
        self.assertIn("Size mismatch", result["message"])
        self.assertEqual(result["filepath"], self.src_file_path)

    @mock.patch('app.shutil.copy2', side_effect=FileNotFoundError("Source not found mock"))
    def test_source_not_found_error(self, mock_copy2):
        # src_path in transfer_file will be self.root_dir / "non_existent_file.txt"
        src_p = self.root_dir / "non_existent_file.txt"
        result = app.transfer_file("non_existent_file.txt", self.root_dir, self.dst_dir)
        
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["filepath"], src_p)
        self.assertIn("Source file not found", result["message"])

    @mock.patch('app.shutil.copy2', side_effect=OSError("Disk full mock"))
    def test_oserror_on_copy(self, mock_copy2):
        result = app.transfer_file(self.filename, self.root_dir, self.dst_dir)

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["filepath"], self.src_file_path)
        self.assertIn("OS error processing", result["message"])
        self.assertIn("Disk full mock", result["message"])


class TestGetHash(unittest.TestCase):
    def setUp(self):
        self.temp_file_holder = tempfile.NamedTemporaryFile(delete=False)
        self.filepath = Path(self.temp_file_holder.name)
        self.content = b"hello world for hashing"
        self.temp_file_holder.write(self.content)
        self.temp_file_holder.close()

    def tearDown(self):
        if self.filepath.exists(): # Ensure unlinking only if it exists
            self.filepath.unlink()

    def test_correct_hashes(self):
        hashes = app.get_hash(self.filepath)
        self.assertIsNotNone(hashes)
        
        md5 = hashlib.md5(self.content).hexdigest()
        sha1 = hashlib.sha1(self.content).hexdigest()
        sha256 = hashlib.sha256(self.content).hexdigest()
        
        self.assertEqual(hashes['md5'], md5)
        self.assertEqual(hashes['sha1'], sha1)
        self.assertEqual(hashes['sha256'], sha256)

    def test_non_existent_file_returns_none(self):
        non_existent_path = Path(self.temp_file_holder.name + "_non_existent")
        self.assertIsNone(app.get_hash(non_existent_path))

    @mock.patch('builtins.open', side_effect=IOError("Failed to open mock"))
    def test_io_error_on_open_returns_none(self, mock_open_function):
        # Filepath exists, but open fails
        self.assertIsNone(app.get_hash(self.filepath))

    @mock.patch('builtins.open')
    def test_io_error_on_read_returns_none(self, mock_open_constructor):
        # Mock the file object returned by open().__enter__()
        mock_file_object = mock.MagicMock()
        mock_file_object.read.side_effect = IOError("Failed to read mock")
        mock_open_constructor.return_value.__enter__.return_value = mock_file_object
        
        self.assertIsNone(app.get_hash(self.filepath))


class TestScanDirectory(unittest.TestCase):
    def setUp(self):
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.temp_dir_path = Path(self.temp_dir_obj.name)
        (self.temp_dir_path / "file1.txt").touch()
        (self.temp_dir_path / "file2.txt").touch()
        self.subdir1_path = self.temp_dir_path / "subdir1"
        self.subdir1_path.mkdir()
        (self.subdir1_path / "file3.txt").touch()

    def tearDown(self):
        self.temp_dir_obj.cleanup()

    def test_yields_correct_paths(self):
        expected_paths = {
            self.temp_dir_path / "file1.txt",
            self.temp_dir_path / "file2.txt",
            self.subdir1_path, # scan_directory yields directories themselves, not their contents recursively
        }
        results = set(app.scan_directory(self.temp_dir_path))
        self.assertEqual(results, expected_paths)

    def test_empty_directory_yields_nothing(self):
        with tempfile.TemporaryDirectory() as empty_dirname:
            empty_dir_path = Path(empty_dirname)
            results = list(app.scan_directory(empty_dir_path))
            self.assertEqual(len(results), 0)

    def test_path_not_exists_raises_file_not_found(self):
        mock_input_path = mock.MagicMock(spec=Path)
        mock_input_path.exists.return_value = False
        # Ensure __str__ is mocked for the error message if the path object is stringified
        mock_input_path.__str__ = mock.Mock(return_value="mock/non_existent_path")

        with self.assertRaisesRegex(FileNotFoundError, "Directory not found: mock/non_existent_path"):
            list(app.scan_directory(mock_input_path))
        mock_input_path.exists.assert_called_once()

    def test_path_is_file_raises_not_a_directory(self):
        mock_input_path = mock.MagicMock(spec=Path)
        mock_input_path.exists.return_value = True
        mock_input_path.is_dir.return_value = False
        mock_input_path.__str__ = mock.Mock(return_value="mock/path_is_file")

        with self.assertRaisesRegex(NotADirectoryError, "Path is not a directory: mock/path_is_file"):
            list(app.scan_directory(mock_input_path))
        mock_input_path.is_dir.assert_called_once()
            
    def test_permission_error_on_iterdir_raises(self):
        # Create a mock Path object that will simulate having permission issues
        mock_input_path = mock.MagicMock(spec=Path)
        mock_input_path.exists.return_value = True
        mock_input_path.is_dir.return_value = True
        # Configure the iterdir method of this specific mock instance to raise PermissionError
        mock_input_path.iterdir.side_effect = PermissionError("Permission denied to list directory")
        mock_input_path.__str__ = mock.Mock(return_value="mock/restricted_dir")

        with self.assertRaisesRegex(PermissionError, "Permission denied to list directory"):
            list(app.scan_directory(mock_input_path))
        mock_input_path.iterdir.assert_called_once()


if __name__ == '__main__':
    # This allows running the tests directly from the script.
    # Note: In some environments (like automated test runners), 
    # this might not be necessary or could interfere.
    # For typical project structures, tests are discovered and run by tools like `python -m unittest discover`.
    unittest.main()
```
