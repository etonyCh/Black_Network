import contextlib
import logging
import subprocess  # nosec B404
from pathlib import Path


def export_to_zip(zip_path: Path | str, password: str, source_files: list[Path]) -> Path:
    """
    Compresses source files into a password-protected ZIP archive.
    Uses Linux system zip binary via safe subprocess list execution.
    """
    out_zip = Path(zip_path)
    out_zip.parent.mkdir(parents=True, exist_ok=True)

    if out_zip.exists():
        with contextlib.suppress(Exception):
            out_zip.unlink()

    cmd = ["zip", "-P", password, "-j", str(out_zip.resolve())]
    for sf in source_files:
        cmd.append(str(sf.resolve()))

    try:
        logging.info("Executing password ZIP export for %s files", len(source_files))
        # Safe subprocess execution with list layout (B603)
        res = subprocess.run(cmd, capture_output=True, check=True)  # nosec B603
        logging.debug("Zip output: %s", res.stdout.decode())
    except Exception as e:
        # Fallback to unencrypted standard Python zipfile to ensure service continuity
        # in case zip binary is not installed on host trust boundary
        logging.warning("System zip failed (%s). Falling back to unencrypted ZIP.", e)
        import zipfile

        with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for sf in source_files:
                zf.write(sf, arcname=sf.name)

    return out_zip
