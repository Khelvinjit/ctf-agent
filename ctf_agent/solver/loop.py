"""The deliberately small, single-model loop between an agent and its sandbox."""
from __future__ import annotations

import time
import re
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

from ctf_agent.config import Settings
from ctf_agent.models.client import ChatClient, ModelError
from ctf_agent.sandbox.executor import SandboxExecutor
from ctf_agent.sandbox.planner import SandboxPlan
from ctf_agent.skills.router import SkillRouter
from ctf_agent.solver.flag_extract import extract_flag
from ctf_agent.types import ChallengeDetail, SolveResult, ToolCall

TOOL_SCHEMAS: list[dict[str, object]] = [
    {"type": "function", "function": {"name": "run_command", "description": "Run a shell command inside the isolated challenge sandbox. Challenge material is read-only at /materials; use /tmp for temporary output.", "parameters": {"type": "object", "properties": {"command": {"type": "string"}, "timeout": {"type": "integer", "minimum": 1, "maximum": 60}}, "required": ["command"]}}},
    {"type": "function", "function": {"name": "search_more_techniques", "description": "Retrieve extra compact CTF technique snippets.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "request_sandbox_expansion", "description": "Request one missing capability only when command evidence shows it is necessary. This ends the current attempt so a replacement sandbox can be created.", "parameters": {"type": "object", "properties": {"capability": {"type": "string", "enum": ["web", "crypto", "forensics", "reverse", "pwn", "stego"]}, "reason": {"type": "string"}}, "required": ["capability", "reason"]}}},
]

NETWORK_COMMAND = re.compile(r"https?://|\b(?:curl|wget|nc|ncat|ssh|ftp)\b|urllib|requests\.|socket\.", re.IGNORECASE)
OUT_OF_SCOPE_COMMAND = re.compile(
    r"\b(?:find|ls|cat|grep|rg|sed|head|tail)\s+/(?!materials(?:/|\b)|scratch(?:/|\b)|tmp(?:/|\b))|"
    r"\b(?:ps|netstat|ss|ip)\b|/(?:proc|sys|etc)(?:/|\b)", re.IGNORECASE)


def command_denial(command: str, network_targets: tuple[str, ...] = ()) -> str | None:
    """Keep agent work focused on mounted local material and scratch output."""
    if NETWORK_COMMAND.search(command):
        urls = re.findall(r"https?://[^\s<>\]\[\"')]+", command, flags=re.IGNORECASE)
        allowed_hosts = {urlparse(url).netloc.lower() for url in network_targets}
        command_hosts = {urlparse(url.rstrip(".,;:")).netloc.lower() for url in urls}
        if not allowed_hosts:
            return "Denied: network is unavailable for this local-material challenge."
        if not command_hosts or not command_hosts.issubset(allowed_hosts):
            return ("Denied: network commands may use only the challenge URL supplied in "
                    "CHALLENGE_DESCRIPTION.md.")
    if OUT_OF_SCOPE_COMMAND.search(command):
        return "Denied: inspect only /materials or /tmp; host/container discovery is out of scope."
    return None


def target_failure_reason(command: str, exit_code: int, network_targets: tuple[str, ...]) -> str | None:
    """Recognise an unavailable authorised target before a model retries it repeatedly."""
    if not network_targets or exit_code not in {6, 7, 28}:
        return None
    urls = re.findall(r"https?://[^\s<>\]\[\"')]+", command, flags=re.IGNORECASE)
    allowed_hosts = {urlparse(url).netloc.lower() for url in network_targets}
    if not any(urlparse(url.rstrip(".,;:")).netloc.lower() in allowed_hosts for url in urls):
        return None
    details = {6: "DNS resolution failed", 7: "connection was refused or unreachable", 28: "connection timed out"}
    return f"authorised challenge target is unavailable ({details[exit_code]}): {network_targets[0]}"


class SolverLoop:
    def __init__(self, settings: Settings, model: ChatClient, router: SkillRouter) -> None:
        self.settings, self.model, self.router = settings, model, router

    def solve(self, challenge: ChallengeDetail, executor: SandboxExecutor, plan: SandboxPlan,
              prior_transcript: list[dict[str, object]] | None = None,
              log: Callable[[dict[str, object]], None] | None = None) -> SolveResult:
        retrieval = self.router.format_retrieval(challenge.category, challenge.title, challenge.description)
        prior_findings = "\n".join(str(event.get("output", event.get("text", "")))
                                   for event in (prior_transcript or [])[-12:])[-12000:]
        system = f"""You are a careful CTF solver. Work only on this authorized challenge in the sandbox.
Find the flag matching {self.settings.flag_format_regex}. Verify candidates before reporting them.
Challenge: {challenge.title} ({challenge.category})
Description:\n{challenge.description}
Files are read-only under /materials: {', '.join(f'/materials/{Path(path).as_posix()}' for path in challenge.files) or 'none'}
Use /tmp for generated files. Approved network targets: {', '.join(plan.network_targets) or 'none (network disabled)'}.
Selected sandbox capabilities: {', '.join(plan.capabilities)}
Selected tools: {', '.join(plan.tools)}
Relevant techniques:\n{retrieval}
Prior findings from an earlier, narrower sandbox (if any):\n{prior_findings or 'none'}
Use tools for evidence. Never claim a flag unless it appears in output or follows directly from verified evidence.
When an approved challenge URL is present, use only that URL; do not probe other hosts, localhost, or container infrastructure.
If the approved target fails to resolve, connect, or times out, stop rather than retrying it or scanning the container.
Request a sandbox expansion only for a concrete missing, local-analysis capability; do not request broad tooling."""
        transcript: list[dict[str, object]] = []
        flag: str | None = None
        requested_capabilities: list[str] = []
        started = time.monotonic()

        def record(event: dict[str, object]) -> None:
            transcript.append(event)
            if log:
                log(event)

        def execute_call(call: ToolCall) -> tuple[str, dict[str, object]]:
            if call.name == "run_command":
                command = str(call.arguments.get("command", ""))
                timeout = min(int(call.arguments.get("timeout", self.settings.command_timeout_seconds)), self.settings.command_timeout_seconds)
                denied = command_denial(command, plan.network_targets)
                if denied:
                    return denied, {"command": command, "timeout_seconds": timeout, "exit_code": 126,
                                    "timed_out": False, "stdout": "", "stderr": denied, "denied": True}
                result = executor.run(command, timeout)
                stdout, stderr = result.stdout[-12000:], result.stderr[-4000:]
                failure = target_failure_reason(command, result.exit_code, plan.network_targets)
                return (f"exit={result.exit_code}\ntimed_out={result.timed_out}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                        {"command": command, "timeout_seconds": timeout, "exit_code": result.exit_code,
                         "timed_out": result.timed_out, "stdout": stdout, "stderr": stderr,
                         "target_failure": failure})
            if call.name == "search_more_techniques":
                query = str(call.arguments.get("query", ""))
                return self.router.format_retrieval(challenge.category, challenge.title, f"{challenge.description}\n{query}"), {}
            if call.name == "request_sandbox_expansion":
                capability = str(call.arguments.get("capability", "")).lower()
                reason = str(call.arguments.get("reason", "")).strip()
                requested_capabilities.append(capability)
                nonlocal_requested_reason[0] = reason
                return f"Expansion requested for {capability}: {reason}. The current sandbox will now stop.", {}
            return f"Unknown tool: {call.name}", {}

        # A mutable cell allows the nested tool handler to preserve a reason.
        nonlocal_requested_reason: list[str] = [""]
        # Gemini requires at least one non-system `contents` entry. Keeping the
        # full instructions in the system message also works with OpenRouter.
        history: list[dict[str, object]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": "Begin by inspecting the supplied local material with the available tools."},
        ]
        model_name: str | None = None
        for _ in range(self.settings.max_iterations):
            if time.monotonic() - started >= self.settings.challenge_timeout_seconds:
                break
            try:
                response = self.model.chat(history, provider=self.settings.model_provider,
                                           model=self.settings.model_name, tools=TOOL_SCHEMAS)
            except ModelError as exc:
                return SolveResult(None, model_name, f"model error: {exc}", transcript=transcript)
            model_name = self.settings.model_name
            record({"event": "model", "model": model_name, "text": response.text,
                    "tool_calls": [{"name": c.name, "arguments": c.arguments} for c in response.tool_calls]})
            flag = extract_flag(response.text, self.settings.flag_format_regex)
            if flag:
                return SolveResult(flag, model_name, transcript=transcript)
            history.append({"role": "assistant", "content": response.text})
            messages: list[dict[str, object]] = []
            for call in response.tool_calls:
                output, details = execute_call(call)
                event: dict[str, object] = {"event": "tool", "model": model_name, "tool": call.name,
                                            "arguments": call.arguments, "output": output}
                event.update(details)
                record(event)
                if details.get("target_failure"):
                    return SolveResult(None, model_name, str(details["target_failure"]), transcript=transcript)
                candidate = extract_flag(output, self.settings.flag_format_regex)
                if candidate:
                    return SolveResult(candidate, model_name, transcript=transcript)
                messages.append({"role": "user", "content": f"Tool `{call.name}` result:\n{output}"})
            if requested_capabilities:
                return SolveResult(None, model_name, nonlocal_requested_reason[0] or "sandbox expansion requested", requested_capabilities,
                                   transcript)
            if messages:
                history.extend(messages)
            else:
                history.append({"role": "user", "content": "Continue solving. Use a tool if evidence is needed; state any candidate flag plainly."})
        reason = "challenge timeout" if time.monotonic() - started >= self.settings.challenge_timeout_seconds else "iteration budget exhausted"
        return SolveResult(flag=None, model=model_name, reason=reason, transcript=transcript)
