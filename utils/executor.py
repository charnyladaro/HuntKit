import subprocess
import shutil
from typing import Optional
from utils.logger import info, warn, error


def is_installed(tool: str) -> bool:
    """Check if a CLI tool is available in PATH."""
    return shutil.which(tool) is not None


def check_tools(tools: list[str]) -> dict[str, bool]:
    """Check multiple tools and return availability map."""
    return {t: is_installed(t) for t in tools}


def run(
    cmd: list[str],
    timeout: int = 300,
    capture: bool = True,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
) -> tuple[int, str, str]:
    """
    Run a subprocess command.
    Returns (returncode, stdout, stderr).
    """
    try:
        proc = subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=capture,
            text=True,
            cwd=cwd,
            env=env,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        warn(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        return -1, "", "timeout"
    except FileNotFoundError:
        error(f"Tool not found: {cmd[0]}")
        return -1, "", "not_found"
    except Exception as e:
        error(f"Error running {cmd[0]}: {e}")
        return -1, "", str(e)


def run_piped(cmd1: list[str], cmd2: list[str], timeout: int = 300) -> tuple[int, str]:
    """Run two commands piped together (cmd1 | cmd2)."""
    try:
        p1 = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        p2 = subprocess.Popen(cmd2, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if p1.stdout:
            p1.stdout.close()
        stdout, _ = p2.communicate(timeout=timeout)
        return p2.returncode, stdout
    except subprocess.TimeoutExpired:
        warn(f"Piped command timed out after {timeout}s")
        return -1, ""
    except Exception as e:
        error(f"Pipe error: {e}")
        return -1, ""


def lines_from(output: str) -> list[str]:
    """Parse stdout into clean list of non-empty lines."""
    return [l.strip() for l in output.splitlines() if l.strip()]
