"""The deliberately small, single-model loop between an agent and its sandbox."""

from __future__ import annotations

import math
import re
import threading
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

from ctf_agent.config import ModelRoute, Settings
from ctf_agent.handoff import format_handoff
from ctf_agent.models.client import ChatClient, ModelError
from ctf_agent.sandbox.executor import (
    CommandResult,
    SandboxExecutor,
    target_transport_failure_reason,
)
from ctf_agent.sandbox.planner import SandboxPlan
from ctf_agent.skills.router import SkillRouter
from ctf_agent.solver.flag_extract import extract_flag
from ctf_agent.types import ChallengeDetail, ModelResponse, SolveResult, ToolCall

TOOL_SCHEMAS: list[dict[str, object]] = [
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Run a shell command inside the isolated challenge sandbox. Challenge material is read-only at /materials; use /tmp for temporary output.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer", "minimum": 1, "maximum": 60},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_more_techniques",
            "description": "Retrieve extra compact CTF technique snippets.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "request_sandbox_expansion",
            "description": "Request one missing capability only when command evidence shows it is necessary. This ends the current attempt so a replacement sandbox can be created.",
            "parameters": {
                "type": "object",
                "properties": {
                    "capability": {
                        "type": "string",
                        "enum": [
                            "web",
                            "crypto",
                            "forensics",
                            "reverse",
                            "pwn",
                            "stego",
                        ],
                    },
                    "reason": {"type": "string"},
                },
                "required": ["capability", "reason"],
            },
        },
    },
]

NETWORK_COMMAND = re.compile(
    r"https?://|\b(?:curl|wget|nc|ncat|ssh|ftp)\b|urllib|requests\.|socket\.",
    re.IGNORECASE,
)
OUT_OF_SCOPE_COMMAND = re.compile(
    r"\b(?:find|ls|cat|grep|rg|sed|head|tail)\s+/(?!materials(?:/|\b)|scratch(?:/|\b)|tmp(?:/|\b))|"
    r"\b(?:ps|netstat|ss|ip)\b|/(?:proc|sys|etc)(?:/|\b)",
    re.IGNORECASE,
)
HISTORY_CHARACTER_BUDGET = 18_000
MESSAGE_CONTENT_CHARACTER_BUDGET = 4_000
COMMAND_STDOUT_CHARACTER_BUDGET = 3_000
COMMAND_STDERR_CHARACTER_BUDGET = 1_000
ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def command_denial(command: str, network_targets: tuple[str, ...] = ()) -> str | None:
    """Keep agent work focused on mounted local material and scratch output."""
    if NETWORK_COMMAND.search(command):
        urls = re.findall(r"https?://[^\s<>\]\[\"')]+", command, flags=re.IGNORECASE)
        allowed_hosts = {urlparse(url).netloc.lower() for url in network_targets}
        command_hosts = {urlparse(url.rstrip(".,;:")).netloc.lower() for url in urls}
        if not allowed_hosts:
            return "Denied: network is unavailable for this local-material challenge."
        if not command_hosts or not command_hosts.issubset(allowed_hosts):
            return (
                "Denied: network commands may use only the challenge URL supplied in "
                "CHALLENGE_DESCRIPTION.md."
            )
    if OUT_OF_SCOPE_COMMAND.search(command):
        return "Denied: inspect only /materials or /tmp; host/container discovery is out of scope."
    return None


def target_failure_reason(
    command: str,
    exit_code: int,
    network_targets: tuple[str, ...],
    output: str = "",
    timed_out: bool = False,
) -> str | None:
    """Recognise an unavailable authorised target before a model retries it repeatedly."""
    if not network_targets:
        return None
    urls = re.findall(r"https?://[^\s<>\]\[\"')]+", command, flags=re.IGNORECASE)
    allowed_hosts = {urlparse(url).netloc.lower() for url in network_targets}
    used_hosts = {urlparse(url.rstrip(".,;:")).netloc.lower() for url in urls}
    matching_targets = [
        target
        for target in network_targets
        if urlparse(target).netloc.lower() in used_hosts
    ]
    if not matching_targets or not used_hosts.issubset(allowed_hosts):
        return None
    return target_transport_failure_reason(
        matching_targets[0], CommandResult("", output, exit_code, timed_out)
    )


def excerpt_command_output(text: str, limit: int) -> tuple[str, int, bool]:
    """Make terminal output useful in a model context without hiding its beginning.

    Disassemblers often emit tens of thousands of coloured characters.  The old
    tail-only slice silently discarded the function header and first basic
    blocks, then history compaction cropped the remainder again.  Preserve both
    ends and explicitly tell the model when it should issue a narrower query.
    """
    clean = ANSI_ESCAPE.sub("", text)
    original_length = len(clean)
    if original_length <= limit:
        return clean, original_length, False
    head = limit // 2
    tail = limit - head
    omitted = original_length - limit
    return (
        f"{clean[:head]}\n… [{omitted} characters omitted; query a narrower range for the middle] …\n"
        f"{clean[-tail:]}",
        original_length,
        True,
    )


def investigation_guidance(category: str) -> str:
    """Return compact, category-aware tool discipline for the solver prompt."""
    universal = """Tool discipline:
- A tool turn is costly. Make each command answer a specific unanswered question; inspect its result before asking a different question.
- Do not repeat a successful inspection, or an equivalent spelling of it, without a new hypothesis. Do not wrap an installed CLI in Python subprocess just to run it.
- The listed programs are the available tools. Do not assume unlisted Python bindings or frameworks are installed.
- Keep output selective. If a result is truncated, query a named function, address range, record, or section rather than requesting another whole-program dump."""
    if category == "reverse":
        return (
            universal
            + """

Reverse workflow:
- First get the executable's observable behaviour with controlled input, then collect compact file/string/symbol triage.
- Once symbols identify input, validation, or flag-output functions, inspect those functions directly before doing global xref or full-function dumps.
- For radare2, invoke the CLI directly with colour disabled and cached relocations (for example `r2 -2 -e bin.cache=true ...`). Avoid rerunning `aaa` unless the binary or analysis state changed. If host binutils cannot disassemble the target architecture, continue with radare2 rather than retrying objdump."""
        )
    if category == "pwn":
        return (
            universal
            + """

Pwn workflow:
- Establish the executable's normal input/output behaviour and mitigations before constructing an exploit. Keep each test deterministic and save any generated input under /tmp."""
        )
    return universal


def compact_history(history: list[dict[str, object]]) -> list[dict[str, object]]:
    """Keep recent, complete tool exchanges within providers' small context quotas."""

    def compact_message(message: dict[str, object]) -> dict[str, object]:
        copied = dict(message)
        content = str(copied.get("content", ""))
        if len(content) > MESSAGE_CONTENT_CHARACTER_BUDGET:
            half = MESSAGE_CONTENT_CHARACTER_BUDGET // 2
            omitted = len(content) - MESSAGE_CONTENT_CHARACTER_BUDGET
            copied["content"] = (
                f"{content[:half]}\n… [{omitted} characters omitted] …\n{content[-half:]}"
            )
        return copied

    # The system prompt and opening user turn establish a valid conversation
    # order for Gemini. Keep later turns as exchange-sized blocks so a function
    # response cannot become separated from its call.
    prefix: list[dict[str, object]] = []
    index = 0
    while index < len(history) and history[index].get("role") == "system":
        prefix.append(compact_message(history[index]))
        index += 1
    if index < len(history) and history[index].get("role") == "user":
        prefix.append(compact_message(history[index]))
        index += 1

    blocks: list[list[dict[str, object]]] = []
    while index < len(history):
        block = [compact_message(history[index])]
        if history[index].get("role") == "assistant" and history[index].get(
            "tool_calls"
        ):
            index += 1
            while index < len(history) and history[index].get("role") == "tool":
                block.append(compact_message(history[index]))
                index += 1
        else:
            index += 1
        blocks.append(block)

    selected: list[list[dict[str, object]]] = []
    used = sum(len(str(message.get("content", ""))) for message in prefix)
    for block in reversed(blocks):
        size = sum(len(str(message.get("content", ""))) for message in block)
        if selected and used + size > HISTORY_CHARACTER_BUDGET:
            break
        selected.append(block)
        used += size
    return prefix + [message for block in reversed(selected) for message in block]


class SolverLoop:
    def __init__(
        self, settings: Settings, model: ChatClient, router: SkillRouter
    ) -> None:
        self.settings, self.model, self.router = settings, model, router

    def solve(
        self,
        challenge: ChallengeDetail,
        executor: SandboxExecutor,
        plan: SandboxPlan,
        prior_transcript: list[dict[str, object]] | None = None,
        log: Callable[[dict[str, object]], None] | None = None,
    ) -> SolveResult:
        retrieval = self.router.format_retrieval(
            challenge.category, challenge.title, challenge.description
        )
        prior_handoff = (
            format_handoff(challenge, plan, prior_transcript or [])
            if prior_transcript
            else "none"
        )
        system = f"""You are a careful CTF solver. Work only on this authorized challenge in the sandbox.
Find the flag matching {self.settings.flag_format_regex}. Verify candidates before reporting them.
Never report a source-code template or placeholder such as `picoCTF{{...}}` as a flag; it is not evidence of a solution.
Challenge: {challenge.title} ({challenge.category})
Description:\n{challenge.description}
Files are read-only under /materials: {", ".join(f"/materials/{Path(path).as_posix()}" for path in challenge.files) or "none"}
Use /tmp for generated files. Approved network targets: {", ".join(plan.network_targets) or "none (network disabled)"}.
Selected sandbox capabilities: {", ".join(plan.capabilities)}
Selected tools: {", ".join(plan.tools)}
Relevant techniques:\n{retrieval}
Prior handoff from an earlier attempt (if any):\n{prior_handoff}
{investigation_guidance(challenge.category)}
Use tools for evidence. Never claim a flag unless it appears in output or follows directly from verified evidence.
When an approved challenge URL is present, use only that URL; do not probe other hosts, localhost, or container infrastructure.
If the approved target fails to resolve, connect, or times out, stop rather than retrying it or scanning the container.
Request a sandbox expansion only for a concrete missing, local-analysis capability; do not request broad tooling."""
        transcript: list[dict[str, object]] = []
        flag: str | None = None
        requested_capabilities: list[str] = []
        started = time.monotonic()
        deadline = started + self.settings.challenge_timeout_seconds

        def remaining_seconds() -> float:
            return deadline - time.monotonic()

        def request_model(
            active_route: ModelRoute, remaining_routes: tuple[ModelRoute, ...]
        ) -> ModelResponse:
            """Do not let a provider request extend the challenge deadline."""
            remaining = remaining_seconds()
            if remaining <= 0:
                raise TimeoutError("challenge timeout")
            response: list[ModelResponse] = []
            failure: list[Exception] = []

            def call() -> None:
                try:
                    options: dict[str, object] = {
                        "provider": active_route.provider,
                        "model": active_route.model,
                        "tools": TOOL_SCHEMAS,
                        "timeout_seconds": max(1, math.ceil(remaining)),
                    }
                    # Only the built-in client supports a restricted fallback
                    # route list. Keep simple test and third-party clients
                    # compatible with their established chat signature.
                    if isinstance(self.model, ChatClient):
                        options["routes"] = remaining_routes
                    response.append(
                        self.model.chat(compact_history(history), **options)
                    )
                except TypeError as exc:
                    # Test and third-party clients that predate the optional
                    # timeout parameter still work; the daemon thread keeps the
                    # solve loop's outward deadline hard.
                    if "timeout_seconds" not in str(exc):
                        failure.append(exc)
                        return
                    try:
                        response.append(
                            self.model.chat(
                                compact_history(history),
                                provider=active_route.provider,
                                model=active_route.model,
                                tools=TOOL_SCHEMAS,
                            )
                        )
                    except (
                        Exception
                    ) as retry_exc:  # pragma: no cover - provider-specific
                        failure.append(retry_exc)
                except Exception as exc:  # pragma: no cover - provider-specific
                    failure.append(exc)

            worker = threading.Thread(target=call, daemon=True)
            worker.start()
            worker.join(remaining)
            if worker.is_alive():
                raise TimeoutError("challenge timeout")
            if failure:
                raise failure[0]
            if not response:
                raise ModelError("model returned no response")
            return response[0]

        def record(event: dict[str, object]) -> None:
            transcript.append(event)
            if log:
                log(event)

        def run_command_before_deadline(command: str, timeout: int) -> CommandResult:
            """Return at the solve deadline even if Docker fails to return."""
            result: list[CommandResult] = []

            def call() -> None:
                result.append(executor.run(command, timeout))

            worker = threading.Thread(target=call, daemon=True)
            worker.start()
            worker.join(max(0, remaining_seconds()))
            if worker.is_alive():
                terminate = getattr(executor, "terminate", None)
                if callable(terminate):
                    terminate()
                return CommandResult(
                    "", "challenge timeout; sandbox terminated", 124, True
                )
            return (
                result[0]
                if result
                else CommandResult("", "sandbox command returned no result", 125)
            )

        def execute_call(call: ToolCall) -> tuple[str, dict[str, object]]:
            if call.name == "run_command":
                command = str(call.arguments.get("command", ""))
                remaining = remaining_seconds()
                if remaining <= 0:
                    return "Challenge deadline reached; command was not started.", {
                        "command": command,
                        "timeout_seconds": 0,
                        "exit_code": 124,
                        "timed_out": True,
                        "stdout": "",
                        "stderr": "challenge timeout",
                    }
                timeout = min(
                    int(
                        call.arguments.get(
                            "timeout", self.settings.command_timeout_seconds
                        )
                    ),
                    self.settings.command_timeout_seconds,
                    max(1, math.floor(remaining)),
                )
                denied = command_denial(command, plan.network_targets)
                if denied:
                    return denied, {
                        "command": command,
                        "timeout_seconds": timeout,
                        "exit_code": 126,
                        "timed_out": False,
                        "stdout": "",
                        "stderr": denied,
                        "denied": True,
                    }
                result = run_command_before_deadline(command, timeout)
                stdout, stdout_size, stdout_truncated = excerpt_command_output(
                    result.stdout, COMMAND_STDOUT_CHARACTER_BUDGET
                )
                stderr, stderr_size, stderr_truncated = excerpt_command_output(
                    result.stderr, COMMAND_STDERR_CHARACTER_BUDGET
                )
                failure = target_failure_reason(
                    command,
                    result.exit_code,
                    plan.network_targets,
                    f"{result.stdout}\n{result.stderr}",
                    result.timed_out,
                )
                return (
                    f"exit={result.exit_code}\ntimed_out={result.timed_out}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                    {
                        "command": command,
                        "timeout_seconds": timeout,
                        "exit_code": result.exit_code,
                        "timed_out": result.timed_out,
                        "stdout": stdout,
                        "stderr": stderr,
                        "stdout_characters": stdout_size,
                        "stderr_characters": stderr_size,
                        "stdout_truncated": stdout_truncated,
                        "stderr_truncated": stderr_truncated,
                        "target_failure": failure,
                    },
                )
            if call.name == "search_more_techniques":
                query = str(call.arguments.get("query", ""))
                return self.router.format_retrieval(
                    challenge.category,
                    challenge.title,
                    f"{challenge.description}\n{query}",
                ), {}
            if call.name == "request_sandbox_expansion":
                capability = str(call.arguments.get("capability", "")).lower()
                reason = str(call.arguments.get("reason", "")).strip()
                requested_capabilities.append(capability)
                nonlocal_requested_reason[0] = reason
                return (
                    f"Expansion requested for {capability}: {reason}. The current sandbox will now stop.",
                    {},
                )
            return f"Unknown tool: {call.name}", {}

        # A mutable cell allows the nested tool handler to preserve a reason.
        nonlocal_requested_reason: list[str] = [""]
        # Gemini requires at least one non-system `contents` entry. Keeping the
        # full instructions in the system message also works with OpenRouter.
        history: list[dict[str, object]] = [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": "Begin by inspecting the supplied local material with the available tools.",
            },
        ]
        model_name: str | None = None
        model_provider: str | None = None
        try:
            routes = self.settings.model_routes()
        except ValueError:
            # Lightweight external/test clients may use a synthetic provider.
            routes = (
                ModelRoute(self.settings.model_provider, self.settings.model_name),
            )
        route_index = 0
        route_iterations = 0
        while route_index < len(routes) and remaining_seconds() > 0:
            active_route = routes[route_index]
            try:
                response = request_model(active_route, routes[route_index:])
            except TimeoutError:
                return SolveResult(
                    None, model_name, "challenge timeout", transcript=transcript
                )
            except ModelError as exc:
                return SolveResult(
                    None, model_name, f"model error: {exc}", transcript=transcript
                )
            model_name = response.model or active_route.model
            model_provider = response.provider or active_route.provider
            actual_route = ModelRoute(model_provider, model_name)
            if actual_route in routes[route_index:] and actual_route != active_route:
                route_index = routes.index(actual_route, route_index)
                route_iterations = 0
                record(
                    {
                        "event": "model_rotation",
                        "reason": "provider fallback",
                        "from_provider": active_route.provider,
                        "from_model": active_route.model,
                        "to_provider": model_provider,
                        "to_model": model_name,
                    }
                )
            record(
                {
                    "event": "model",
                    "provider": model_provider,
                    "model": model_name,
                    "rate_limited_routes": response.rate_limited_routes,
                    "unavailable_routes": response.unavailable_routes,
                    "text": response.text,
                    "tool_calls": [
                        {"name": c.name, "arguments": c.arguments}
                        for c in response.tool_calls
                    ],
                }
            )
            flag = extract_flag(response.text, self.settings.flag_format_regex)
            if flag:
                return SolveResult(flag, model_name, transcript=transcript)
            history.append(
                {
                    "role": "assistant",
                    "content": response.text,
                    "tool_calls": response.tool_calls,
                }
            )
            messages: list[dict[str, object]] = []
            for call in response.tool_calls:
                output, details = execute_call(call)
                event: dict[str, object] = {
                    "event": "tool",
                    "provider": model_provider,
                    "model": model_name,
                    "tool": call.name,
                    "arguments": call.arguments,
                    "output": output,
                }
                event.update(details)
                record(event)
                if details.get("target_failure"):
                    return SolveResult(
                        None,
                        model_name,
                        str(details["target_failure"]),
                        transcript=transcript,
                    )
                candidate = extract_flag(output, self.settings.flag_format_regex)
                if candidate:
                    return SolveResult(candidate, model_name, transcript=transcript)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id or call.name,
                        "name": call.name,
                        "content": output,
                    }
                )
            if requested_capabilities:
                return SolveResult(
                    None,
                    model_name,
                    nonlocal_requested_reason[0] or "sandbox expansion requested",
                    requested_capabilities,
                    transcript,
                )
            if messages:
                history.extend(messages)
            else:
                history.append(
                    {
                        "role": "user",
                        "content": "Continue solving. Use a tool if evidence is needed; state any candidate flag plainly.",
                    }
                )
            route_iterations += 1
            if route_iterations < self.settings.max_iterations:
                continue
            if actual_route in routes[route_index:]:
                route_index = routes.index(actual_route, route_index)
            if route_index + 1 >= len(routes):
                break
            next_route = routes[route_index + 1]
            record(
                {
                    "event": "model_rotation",
                    "reason": "iteration budget exhausted",
                    "from_provider": model_provider,
                    "from_model": model_name,
                    "to_provider": next_route.provider,
                    "to_model": next_route.model,
                }
            )
            handoff = format_handoff(
                challenge,
                plan,
                transcript,
                reason="previous route exhausted its iteration budget",
            )
            history.append(
                {
                    "role": "user",
                    "content": (
                        "The previous model used its iteration budget. Continue from this handoff brief and the available "
                        "tool history; do not repeat completed work. Start by forming one new, testable hypothesis.\n\n"
                        f"{handoff}"
                    ),
                }
            )
            route_index += 1
            route_iterations = 0
        reason = (
            "challenge timeout"
            if remaining_seconds() <= 0
            else "iteration budget exhausted for all configured model routes"
        )
        return SolveResult(
            flag=None, model=model_name, reason=reason, transcript=transcript
        )
