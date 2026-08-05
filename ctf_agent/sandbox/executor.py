from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(slots=True)
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False


class SandboxExecutor:
    def __init__(self, container_id: str, timeout_seconds: int = 60) -> None:
        self.container_id, self.timeout_seconds = container_id, timeout_seconds

    def run(self, command: str, timeout: int | None = None) -> CommandResult:
        try:
            completed = subprocess.run(["docker", "exec", self.container_id, "bash", "-lc", command],
                text=True, capture_output=True, timeout=timeout or self.timeout_seconds, check=False)
            return CommandResult(completed.stdout, completed.stderr, completed.returncode)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout or ""
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else exc.stderr or ""
            return CommandResult(stdout, stderr, 124, True)
