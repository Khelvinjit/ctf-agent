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
    def __init__(self, container_id: str, timeout_seconds: int = 60, *,
                 egress_proxy_id: str | None = None, egress_network: str | None = None) -> None:
        self.container_id, self.timeout_seconds = container_id, timeout_seconds
        self.egress_proxy_id, self.egress_network = egress_proxy_id, egress_network
        self.terminated = False

    def terminate(self) -> None:
        """Destroy this sandbox when an outer deadline expires."""
        if self.terminated:
            return
        subprocess.run(["docker", "kill", self.container_id], text=True, capture_output=True, check=False)
        self.terminated = True

    def run(self, command: str, timeout: int | None = None) -> CommandResult:
        if self.terminated:
            return CommandResult("", "sandbox has been terminated", 125)
        limit = max(1, min(timeout or self.timeout_seconds, self.timeout_seconds))
        # GNU timeout runs *inside* the container, so the command receives TERM
        # and then KILL even when the host-side Docker client stays healthy.
        wrapped = f'exec timeout --signal=TERM --kill-after=5s {limit}s bash -lc "$1"'
        try:
            completed = subprocess.run(["docker", "exec", self.container_id, "bash", "-lc", wrapped,
                                        "--", command], text=True, capture_output=True,
                                       timeout=limit + 10, check=False)
            return CommandResult(completed.stdout, completed.stderr, completed.returncode,
                                 completed.returncode == 124)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout or ""
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else exc.stderr or ""
            # If Docker itself fails to return after the in-container grace
            # period, destroy the whole sandbox. This prevents orphaned work.
            self.terminate()
            return CommandResult(stdout, stderr, 124, True)
