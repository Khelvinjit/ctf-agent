from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path

import pytest

from ctf_agent.classifier import ThemeClassifier, ThemeDecision, assert_safe_materials, challenge_urls, inventory_materials
from ctf_agent.config import Settings
from ctf_agent.models.client import ChatClient
from ctf_agent.sandbox.planner import SandboxPlan, SandboxPlanner
from ctf_agent.skills.build_index import build_index
from ctf_agent.skills.router import SkillRouter
from ctf_agent.solver.flag_extract import extract_flag
from ctf_agent.solver.loop import SolverLoop, command_denial, target_failure_reason
from ctf_agent.types import ChallengeDetail, ModelResponse, ToolCall


def test_flag_extract() -> None:
    assert extract_flag("answer picoCTF{works}", r"picoCTF\{[^}]+\}") == "picoCTF{works}"
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


def test_solver_rejects_remote_and_out_of_scope_commands() -> None:
    assert "network" in str(command_denial("curl http://example.test"))
    assert "out of scope" in str(command_denial("find / -name app.py"))
    assert command_denial("find /materials -type f") is None
    target = ("http://challenge.example:8080/",)
    assert command_denial("curl http://challenge.example:8080/login", target) is None
    assert "only the challenge URL" in str(command_denial("curl http://other.example/", target))
    assert "unavailable" in str(target_failure_reason("curl http://challenge.example:8080/", 7, target))
