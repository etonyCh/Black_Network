import subprocess  # nosec B404
from typing import Any


class SubprocessExecutionError(Exception):
    pass


def safe_run(
    args: list[str], timeout: float | None = 30.0, check: bool = True, **kwargs: Any
) -> subprocess.CompletedProcess[str]:
    """
    Executes a system command safely.
    Strictly forbids running with shell=True or passing command as a raw string.
    """
    # Guard against shell injection
    if kwargs.get("shell") is True:
        raise ValueError("Usage of shell=True is strictly prohibited for security reasons.")

    if not isinstance(args, list):
        raise TypeError("args must be a list of strings representing the argv array.")

    # Ensure all elements in argv are strings
    for i, arg in enumerate(args):
        if not isinstance(arg, str):
            raise TypeError(f"All elements in args must be strings. Index {i} is {type(arg)}")

    try:
        # Override dangerous parameters
        kwargs["shell"] = False

        # Run command capturing stdout and stderr
        return subprocess.run(  # nosec B603
            args, capture_output=True, text=True, timeout=timeout, check=check, **kwargs
        )
    except subprocess.TimeoutExpired as e:
        raise SubprocessExecutionError(
            f"Command execution timed out after {timeout} seconds: {e}"
        ) from e
    except subprocess.CalledProcessError as e:
        raise SubprocessExecutionError(
            f"Command failed with exit code {e.returncode}.\n"
            f"Command: {' '.join(args)}\n"
            f"Stderr: {e.stderr}"
        ) from e
    except FileNotFoundError as e:
        raise SubprocessExecutionError(f"Executable not found: {args[0]}") from e
    except Exception as e:
        raise SubprocessExecutionError(f"Unexpected error executing command: {e}") from e
