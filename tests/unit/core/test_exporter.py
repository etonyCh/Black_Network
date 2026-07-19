import subprocess
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

from netsentinel.core.audit.exporter import export_to_zip


def test_export_to_zip_success():
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = Path(tmpdir)
        file1 = src_dir / "test1.txt"
        file1.write_text("Hello file 1")

        zip_path = src_dir / "export.zip"
        res_path = export_to_zip(zip_path, "secret_password", [file1])

        assert res_path.exists()

        # Verify content can be opened using the password
        with zipfile.ZipFile(res_path) as zf:
            assert "test1.txt" in zf.namelist()
            assert zf.read("test1.txt", pwd=b"secret_password") == b"Hello file 1"

        # Cleanup
        zip_path.unlink()


@patch("netsentinel.core.audit.exporter.subprocess.run")
def test_export_to_zip_fallback(mock_run):
    # Mock subprocess to fail to force fallback
    mock_run.side_effect = subprocess.CalledProcessError(1, "zip")

    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = Path(tmpdir)
        file1 = src_dir / "test1.txt"
        file1.write_text("Hello fallback 1")

        zip_path = src_dir / "export_fallback.zip"
        res_path = export_to_zip(zip_path, "secret_password", [file1])

        assert res_path.exists()

        # Verify unencrypted fallback zip
        with zipfile.ZipFile(res_path) as zf:
            assert "test1.txt" in zf.namelist()
            assert zf.read("test1.txt") == b"Hello fallback 1"

        zip_path.unlink()
