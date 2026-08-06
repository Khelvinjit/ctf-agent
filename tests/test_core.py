from __future__ import annotations

import importlib.util
import time
import zipfile
from pathlib import Path

import pytest

from ctf_agent.classifier import ThemeClassifier, ThemeDecision, assert_safe_materials, challenge_urls, inventory_materials
from ctf_agent.config import Settings
from ctf_agent.models.client import ChatClient
from ctf_agent.sandbox.executor import CommandResult
from ctf_agent.sandbox.planner import SandboxPlan, SandboxPlanner
from ctf_agent.skills.build_index import build_index
from ctf_agent.skills.router import SkillRouter
from ctf_agent.solver.flag_extract import extract_flag
from ctf_agent.solver.loop import TOOL_SCHEMAS, SolverLoop, command_denial, target_failure_reason
from ctf_agent.types import ChallengeDetail, ModelResponse, ToolCall


def test_flag_extract() -> None:
    assert extract_flag("answer picoCTF{works}", r"picoCTF\{[^}]+\}") == "picoCTF{works}"
    assert extract_flag('template = "picoCTF{...}"', r"picoCTF\{[^}]+\}") is None
    assert extract_flag("picoCTF{...} then picoCTF{real_flag}", r"picoCTF\{[^}]+\}") == "picoCTF{real_flag}"
    assert extract_flag("nothing", r"FLAG\{[^}]+\}") is None


def test_description_metadata_contract() -> None:
    script = Path(__file__).parents[1] / "scripts" / "solve_manual.py"
    spec = importlib.util.spec_from_file_location("solve_manual", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.metadata("decode this strange ciphertext\n\nanything else") == ("decode this strange ciphertext", "unknown")
    assert module.metadata("\n\n") == ("pasted challenge", "unknown")


def test_inventory_lists_archive_without_extracting(tmp_path: Path) -> None:
    (tmp_path / "CHALLENGE_DESCRIPTION.md").write_text("# Test")
    archive = tmp_path / "evidence.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("nested/flag.txt", "not extracted")
    inventory = inventory_materials(tmp_path)
    record = next(item for item in inventory if item.path == "evidence.zip")
    assert record.sha256
    assert record.archive_members == ("nested/flag.txt",)
    assert not (tmp_path / "nested").exists()


def test_inventory_rejects_symlink(tmp_path: Path) -> None:
    (tmp_path / "CHALLENGE_DESCRIPTION.md").write_text("# Test")
    (tmp_path / "outside.txt").symlink_to("/etc/hosts")
    with pytest.raises(ValueError, match="symlinks"):
        assert_safe_materials(tmp_path)


class ClassifierClient:
    def __init__(self) -> None:
        self.calls = 0

    def chat(self, *args: object, **kwargs: object) -> ModelResponse:
        self.calls += 1
        if self.calls == 1:
            return ModelResponse(text='{"theme":"crypto","confidence":0.9,"evidence":["ciphertext file"],"unknowns":[]}')
        return ModelResponse(text='{"initial_capabilities":["crypto"]}')


def test_agent_theme_decision_becomes_minimal_plan(tmp_path: Path) -> None:
    (tmp_path / "cipher.txt").write_text("uryyb")
    client = ClassifierClient()
    decision = ThemeClassifier(client, "fake", "fake").classify(
        "decode this", "unknown", inventory_materials(tmp_path))
    plan = SandboxPlanner().create(decision)
    assert decision.theme == "crypto"
    assert client.calls == 2
    assert plan.capabilities == ("base", "crypto")
    assert "gdb" not in plan.tools


def test_planner_only_expands_within_theme() -> None:
    plan = SandboxPlan("forensics", ("base", "forensics"), ("python3", "exiftool"), ("image",))
    expanded = SandboxPlanner().expand(plan, ["stego"], "image has hidden data")
    assert expanded and expanded.capabilities == ("base", "forensics", "stego")
    assert SandboxPlanner().expand(plan, ["pwn"], "unrelated") is None


def test_web_url_enables_only_that_sandbox_plan() -> None:
    decision = ThemeDecision("web", 1.0, ("explicit URL",), ("web",))
    targets = challenge_urls("Target: http://challenge.example:8080/path")
    plan = SandboxPlanner().create(decision, targets)
    assert plan.network_targets == targets
    assert plan.network_enabled


def test_skill_index_and_router(tmp_path: Path) -> None:
    source = tmp_path / "ctf-crypto"; source.mkdir()
    (source / "SKILL.md").write_text("# Classical ciphers\n- Kasiski examination\n  Vigenere cipher repeated sequence analysis.\n")
    index = tmp_path / "index.sqlite"
    assert build_index(tmp_path, index) == 2
    items = SkillRouter(index).retrieve("Cryptography", "Vigenere warmup", "decode this cipher")
    assert any("Kasiski" in item["name"] for item in items)


class FakeClient:
    def chat(self, *args: object, **kwargs: object) -> ModelResponse:
        return ModelResponse(tool_calls=[ToolCall("run_command", {"command": "echo picoCTF{caesar}"})])


class FakeExecutor:
    def run(self, command: str, timeout: int | None = None):
        from ctf_agent.sandbox.executor import CommandResult
        return CommandResult("picoCTF{caesar}\n", "", 0)


def test_solver_stops_on_flag_from_tool(tmp_path: Path) -> None:
    settings = Settings(model_provider="fake", model_name="fake-model", max_iterations=2,
                        flag_format_regex=r"picoCTF\{[^}]+\}")
    plan = SandboxPlan("crypto", ("base", "crypto"), ("python3",), ("cipher",))
    result = SolverLoop(settings, FakeClient(), SkillRouter(tmp_path / "missing.sqlite")).solve(
        ChallengeDetail("id", "Caesar", "crypto", description="decode"), FakeExecutor(), plan)
    assert result.flag == "picoCTF{caesar}"
    assert result.model == "fake-model"
    command_event = next(event for event in result.transcript if event["event"] == "tool")
    assert command_event["command"] == "echo picoCTF{caesar}"
    assert "timed_out=False" in str(command_event["output"])


def test_solver_sends_tool_result_back_before_the_next_model_turn(tmp_path: Path) -> None:
    class TwoTurnClient:
        def __init__(self) -> None:
            self.histories: list[list[dict[str, object]]] = []

        def chat(self, messages: list[dict[str, object]], **kwargs: object) -> ModelResponse:
            self.histories.append(messages.copy())
            if len(self.histories) == 1:
                return ModelResponse(tool_calls=[ToolCall("run_command", {"command": "echo evidence"}, id="call_1")])
            assert messages[-1]["role"] == "tool"
            assert messages[-1]["tool_call_id"] == "call_1"
            return ModelResponse(text="picoCTF{continued}")

    client = TwoTurnClient()
    class EvidenceExecutor:
        def run(self, command: str, timeout: int | None = None):
            from ctf_agent.sandbox.executor import CommandResult
            return CommandResult("evidence\n", "", 0)

    settings = Settings(model_provider="fake", model_name="fake-model", max_iterations=2,
                        flag_format_regex=r"picoCTF\{[^}]+\}")
    plan = SandboxPlan("crypto", ("base", "crypto"), ("python3",), ("cipher",))
    result = SolverLoop(settings, client, SkillRouter(tmp_path / "missing.sqlite")).solve(
        ChallengeDetail("id", "Continuation", "crypto"), EvidenceExecutor(), plan)
    assert result.flag == "picoCTF{continued}"


def test_gemini_request_keeps_a_user_content_entry() -> None:
    class Response:
        status_code = 200
        is_error = False
        text = ""
        def json(self):
            return {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}

    class Http:
        payload: dict[str, object]
        def request(self, method: str, url: str, **kwargs: object) -> Response:
            self.payload = kwargs["json"]  # type: ignore[assignment]
            return Response()

    http = Http()
    client = ChatClient(Settings(gemini_api_key="test"), http)  # type: ignore[arg-type]
    response = client.chat([{"role": "system", "content": "instructions"},
                            {"role": "user", "content": "begin"}], provider="gemini", model="test")
    assert response.text == "ok"
    assert http.payload["contents"] == [{"role": "user", "parts": [{"text": "begin"}]}]


def test_rate_limit_rotates_from_gemini_to_groq() -> None:
    class Response:
        def __init__(self, status_code: int, payload: dict[str, object] | None = None) -> None:
            self.status_code = status_code
            self.is_error = status_code >= 400
            self.text = "quota" if status_code == 429 else ""
            self.payload = payload or {}

        def json(self):
            return self.payload

    class Http:
        def __init__(self) -> None:
            self.urls: list[str] = []

        def request(self, method: str, url: str, **kwargs: object) -> Response:
            self.urls.append(url)
            if "generativelanguage" in url:
                return Response(429)
            return Response(200, {"choices": [{"message": {"content": "groq response"}}]})

    http = Http()
    settings = Settings(gemini_api_key="gemini", groq_api_key="groq",
                        model_rotation="gemini:gemini-2.5-flash,groq:openai/gpt-oss-120b")
    response = ChatClient(settings, http).chat(  # type: ignore[arg-type]
        [{"role": "user", "content": "begin"}], provider="gemini", model="gemini-2.5-flash")
    assert response.text == "groq response"
    assert (response.provider, response.model) == ("groq", "openai/gpt-oss-120b")
    assert response.rate_limited_routes == ("gemini:gemini-2.5-flash",)
    assert "generativelanguage" in http.urls[0]
    assert http.urls[1] == "https://api.groq.com/openai/v1/chat/completions"


def test_missing_gemini_model_rotates_to_groq() -> None:
    class Response:
        def __init__(self, status_code: int, payload: dict[str, object] | None = None) -> None:
            self.status_code = status_code
            self.is_error = status_code >= 400
            self.text = "model not found" if status_code == 404 else ""
            self.payload = payload or {}

        def json(self):
            return self.payload

    class Http:
        def request(self, method: str, url: str, **kwargs: object) -> Response:
            if "generativelanguage" in url:
                return Response(404)
            return Response(200, {"choices": [{"message": {"content": "fallback response"}}]})

    settings = Settings(gemini_api_key="gemini", groq_api_key="groq",
                        model_rotation="gemini:missing-model,groq:openai/gpt-oss-120b")
    response = ChatClient(settings, Http()).chat(  # type: ignore[arg-type]
        [{"role": "user", "content": "begin"}], provider="gemini", model="missing-model")
    assert (response.provider, response.model) == ("groq", "openai/gpt-oss-120b")
    assert response.unavailable_routes == ("gemini:missing-model",)


def test_provider_serializers_keep_native_tool_result_shape() -> None:
    call = ToolCall("run_command", {"command": "file /materials/a"}, id="call_1",
                    thought_signature="opaque-gemini-signature")
    messages = [
        {"role": "system", "content": "instructions"},
        {"role": "user", "content": "begin"},
        {"role": "assistant", "content": "", "tool_calls": [call]},
        {"role": "tool", "tool_call_id": "call_1", "name": "run_command", "content": "text file"},
    ]
    openrouter = ChatClient._openrouter_messages(messages)
    assert openrouter[2]["tool_calls"] == [{"id": "call_1", "type": "function", "function": {
        "name": "run_command", "arguments": '{"command": "file /materials/a"}'}}]
    assert openrouter[3] == {"role": "tool", "content": "text file", "tool_call_id": "call_1", "name": "run_command"}
    gemini = ChatClient._gemini_contents(messages)
    assert gemini[1]["parts"] == [{"functionCall": {"name": "run_command", "args": {"command": "file /materials/a"}},
                                    "thoughtSignature": "opaque-gemini-signature"}]
    assert gemini[2]["parts"] == [{"functionResponse": {"name": "run_command", "response": {"result": "text file"}}}]


def test_gemini_parser_preserves_thought_signature() -> None:
    class Response:
        status_code = 200
        is_error = False
        text = ""
        def json(self):
            return {"candidates": [{"content": {"parts": [{"functionCall": {
                "name": "run_command", "args": {"command": "file /materials/a"},
                "id": "call-from-api"}, "thoughtSignature": "opaque-gemini-signature"}]}}]}

    class Http:
        def request(self, *args: object, **kwargs: object) -> Response:
            return Response()

    response = ChatClient(Settings(gemini_api_key="test"), Http()).chat(  # type: ignore[arg-type]
        [{"role": "user", "content": "begin"}], provider="gemini", model="test", tools=TOOL_SCHEMAS)
    assert response.tool_calls[0].thought_signature == "opaque-gemini-signature"
    assert response.tool_calls[0].id == "call-from-api"


def test_gemini_serializer_groups_parallel_tool_results() -> None:
    messages = [
        {"role": "tool", "tool_call_id": "one", "name": "first", "content": "first result"},
        {"role": "tool", "tool_call_id": "two", "name": "second", "content": "second result"},
    ]
    assert ChatClient._gemini_contents(messages) == [{"role": "user", "parts": [
        {"functionResponse": {"name": "first", "response": {"result": "first result"}}},
        {"functionResponse": {"name": "second", "response": {"result": "second result"}}},
    ]}]


def test_solver_rejects_remote_and_out_of_scope_commands() -> None:
    assert "network" in str(command_denial("curl http://example.test"))
    assert "out of scope" in str(command_denial("find / -name app.py"))
    assert command_denial("find /materials -type f") is None
    target = ("http://challenge.example:8080/",)
    assert command_denial("curl http://challenge.example:8080/login", target) is None
    assert "only the challenge URL" in str(command_denial("curl http://other.example/", target))
    assert "unavailable" in str(target_failure_reason("curl http://challenge.example:8080/", 7, target))


def test_solver_returns_at_the_hard_deadline(tmp_path: Path) -> None:
    class SlowClient:
        def chat(self, *args: object, **kwargs: object) -> ModelResponse:
            time.sleep(2)
            return ModelResponse(text="too late")

    settings = Settings(model_provider="fake", model_name="fake-model", challenge_timeout_seconds=1)
    plan = SandboxPlan("misc", ("base",), ("python3",), ("unknown",))
    started = time.monotonic()
    result = SolverLoop(settings, SlowClient(), SkillRouter(tmp_path / "missing.sqlite")).solve(
        ChallengeDetail("id", "Slow", "misc"), FakeExecutor(), plan)
    assert result.reason == "challenge timeout"
    assert time.monotonic() - started < 1.5


def test_solver_deadline_terminates_a_slow_command(tmp_path: Path) -> None:
    class CommandClient:
        def chat(self, *args: object, **kwargs: object) -> ModelResponse:
            return ModelResponse(tool_calls=[ToolCall("run_command", {"command": "sleep 60"})])

    class SlowExecutor:
        def __init__(self) -> None:
            self.terminated = False

        def run(self, command: str, timeout: int | None = None) -> CommandResult:
            time.sleep(2)
            return CommandResult("", "", 0)

        def terminate(self) -> None:
            self.terminated = True

    settings = Settings(model_provider="fake", model_name="fake-model", challenge_timeout_seconds=1)
    executor = SlowExecutor()
    plan = SandboxPlan("misc", ("base",), ("python3",), ("unknown",))
    started = time.monotonic()
    result = SolverLoop(settings, CommandClient(), SkillRouter(tmp_path / "missing.sqlite")).solve(
        ChallengeDetail("id", "Slow command", "misc"), executor, plan)  # type: ignore[arg-type]
    assert result.reason == "challenge timeout"
    assert executor.terminated
    assert time.monotonic() - started < 1.5


def test_egress_proxy_rejects_private_or_undeclared_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    proxy_path = Path(__file__).parents[1] / "docker" / "egress_proxy.py"
    monkeypatch.setenv("EGRESS_TARGETS", '["https://challenge.example:8443/path"]')
    spec = importlib.util.spec_from_file_location("egress_proxy_test", proxy_path)
    assert spec and spec.loader
    proxy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proxy)
    with pytest.raises(PermissionError, match="approved"):
        proxy.permitted_address("other.example", 443)
    monkeypatch.setattr(proxy.socket, "getaddrinfo", lambda *args, **kwargs: [
        (proxy.socket.AF_INET, proxy.socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8443))])
    with pytest.raises(PermissionError, match="non-public"):
        proxy.permitted_address("challenge.example", 8443)
