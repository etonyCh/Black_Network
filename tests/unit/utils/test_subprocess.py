import pytest

from netsentinel.utils.subprocess_safe import SubprocessExecutionError, safe_run


def test_safe_run_success():
    res = safe_run(["echo", "hello"])
    assert res.returncode == 0
    assert "hello" in res.stdout


def test_safe_run_shell_blocked():
    with pytest.raises(ValueError, match="shell=True is strictly prohibited"):
        safe_run(["echo", "hello"], shell=True)  # type: ignore[call-overload]


def test_safe_run_invalid_args():
    with pytest.raises(TypeError, match="args must be a list of strings"):
        safe_run("echo hello")  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="All elements in args must be strings"):
        safe_run(["echo", 123])  # type: ignore[list-item]


def test_safe_run_command_not_found():
    with pytest.raises(SubprocessExecutionError, match="Executable not found"):
        safe_run(["nonexistentbinaryabc123"])


def test_safe_run_failure():
    # Run a command that exits with non-zero code
    with pytest.raises(SubprocessExecutionError, match="Command failed with exit code"):
        safe_run(["false"])


def test_safe_run_timeout():
    # Run a command that sleeps and specify short timeout
    # 'sleep' command arguments
    # Avoid sleeping too long in tests
    with pytest.raises(SubprocessExecutionError, match="timed out after"):
        safe_run(["sleep", "2"], timeout=0.1)
