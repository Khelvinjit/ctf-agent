from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass


@dataclass(slots=True)
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False


@dataclass(slots=True)
class TargetPreflight:
    """The result of one proxy-routed request to an approved challenge URL."""

    target: str
    command: str
    result: CommandResult
    reachable: bool
    reason: str | None = None


def target_transport_failure_reason(target: str, result: CommandResult) -> str | None:
    """Return a stable infrastructure diagnosis for common network failures.

    A solver cannot distinguish an unavailable remote target from a difficult
    challenge by repeatedly issuing equivalent requests.  Keep this limited to
    transport-level failures so application HTTP responses remain available to
    the agent as evidence.
    """
    output = f"{result.stdout}\n{result.stderr}".lower()
    if result.timed_out or result.exit_code == 28 or "connection timed out" in output:
        detail = "connection timed out"
    elif (
        result.exit_code == 5
        or "could not resolve proxy" in output
        or ("proxyerror" in output and "resolve" in output)
    ):
        detail = "egress proxy could not be resolved"
    elif (
        result.exit_code == 6
        or "temporary failure in name resolution" in output
        or ("name or service not known" in output and "proxy" not in output)
    ):
        detail = "target DNS resolution failed"
    elif (
        result.exit_code == 7
        or "network is unreachable" in output
        or "couldn't connect to server" in output
        or ("failed to connect to" in output and "http" in output)
    ):
        detail = "connection was refused or unreachable"
    else:
        return None
    return f"authorised challenge target is unavailable ({detail}): {target}"


class SandboxExecutor:
    def __init__(
        self,
        container_id: str,
        timeout_seconds: int = 60,
        *,
        egress_proxy_id: str | None = None,
        egress_network: str | None = None,
    ) -> None:
        self.container_id, self.timeout_seconds = container_id, timeout_seconds
        self.egress_proxy_id, self.egress_network = egress_proxy_id, egress_network
        self.terminated = False

    def terminate(self) -> None:
        """Destroy this sandbox when an outer deadline expires."""
        if self.terminated:
            return
        subprocess.run(
            ["docker", "kill", self.container_id],
            text=True,
            capture_output=True,
            check=False,
        )
        self.terminated = True

    def run(self, command: str, timeout: int | None = None) -> CommandResult:
        if self.terminated:
            return CommandResult("", "sandbox has been terminated", 125)
        limit = max(1, min(timeout or self.timeout_seconds, self.timeout_seconds))
        # GNU timeout runs *inside* the container, so the command receives TERM
        # and then KILL even when the host-side Docker client stays healthy.
        wrapped = f'exec timeout --signal=TERM --kill-after=5s {limit}s bash -lc "$1"'
        try:
            completed = subprocess.run(
                [
                    "docker",
                    "exec",
                    self.container_id,
                    "bash",
                    "-lc",
                    wrapped,
                    "--",
                    command,
                ],
                text=True,
                capture_output=True,
                timeout=limit + 10,
                check=False,
            )
            return CommandResult(
                completed.stdout,
                completed.stderr,
                completed.returncode,
                completed.returncode == 124,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = (
                exc.stdout.decode()
                if isinstance(exc.stdout, bytes)
                else exc.stdout or ""
            )
            stderr = (
                exc.stderr.decode()
                if isinstance(exc.stderr, bytes)
                else exc.stderr or ""
            )
            # If Docker itself fails to return after the in-container grace
            # period, destroy the whole sandbox. This prevents orphaned work.
            self.terminate()
            return CommandResult(stdout, stderr, 124, True)

    def preflight_target(self, target: str, timeout: int = 12) -> TargetPreflight:
        """Verify one declared target through the sandbox's configured proxy.

        The request intentionally uses GET rather than HEAD because small CTF
        services often implement only the former.  Any HTTP response proves
        that routing works; the solver will interpret its status and body.
        """
        limit = max(1, min(timeout, self.timeout_seconds))
        command = (
            "curl --silent --show-error --output /dev/null --write-out '%{http_code}' "
            f"--connect-timeout {min(5, limit)} --max-time {limit} -- {shlex.quote(target)}"
        )
        result = self.run(command, limit)
        reason = target_transport_failure_reason(target, result)
        if result.exit_code != 0 and reason is None:
            detail = (
                result.stderr.strip()
                or result.stdout.strip()
                or f"curl exited with status {result.exit_code}"
            )
            reason = (
                f"authorised challenge target preflight failed: {target} ({detail})"
            )
        return TargetPreflight(target, command, result, result.exit_code == 0, reason)
