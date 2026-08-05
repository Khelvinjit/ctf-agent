from __future__ import annotations

import subprocess
import hashlib
from pathlib import Path

from ctf_agent.classifier import assert_safe_materials
from ctf_agent.config import Settings
from ctf_agent.sandbox.executor import SandboxExecutor
from ctf_agent.sandbox.planner import SandboxPlan


class SandboxManager:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def project_root(self) -> Path:
        return Path(__file__).resolve().parents[2]

    def build_fingerprint(self, plan: SandboxPlan) -> str:
        dockerfile = self.project_root / "docker" / "Dockerfile.sandbox"
        digest = hashlib.sha256()
        digest.update(plan.fingerprint.encode())
        digest.update(dockerfile.read_bytes())
        return digest.hexdigest()

    def image_for(self, plan: SandboxPlan) -> str:
        return f"{self.settings.sandbox_image}:{self.build_fingerprint(plan)[:16]}"

    def ensure_image(self, plan: SandboxPlan) -> str:
        """Build only the selected capability set, and cache it by manifest hash."""
        image = self.image_for(plan)
        present = subprocess.run(["docker", "image", "inspect", image], text=True,
                                 capture_output=True, check=False)
        if present.returncode == 0:
            print(f"Using cached sandbox image: {image}", flush=True)
            return image
        print(f"Building sandbox image for: {', '.join(plan.capabilities)}", flush=True)
        completed = subprocess.run([
            "docker", "build", "--build-arg", f"SANDBOX_CAPABILITIES={','.join(plan.capabilities)}",
            "--build-arg", f"SANDBOX_REVISION={self.build_fingerprint(plan)}", "-f",
            str(self.project_root / "docker" / "Dockerfile.sandbox"), "-t", image,
            str(self.project_root),
        ], text=True, check=False)
        if completed.returncode:
            raise RuntimeError(f"sandbox image build exited with status {completed.returncode}")
        return image

    def start(self, materials_dir: Path, plan: SandboxPlan) -> SandboxExecutor:
        assert_safe_materials(materials_dir)
        image = self.ensure_image(plan)
        network_args = [] if plan.network_enabled else ["--network", "none"]
        network_label = "target-authorized network" if plan.network_enabled else "no-network"
        print(f"Starting isolated, {network_label} sandbox…", flush=True)
        completed = subprocess.run(["docker", "run", "--rm", "-d", *network_args, "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit",
            str(self.settings.sandbox_pids_limit), "--memory", self.settings.sandbox_memory,
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--user", "solver", "-v",
            f"{materials_dir.resolve()}:/materials:ro", "-w", "/tmp", image],
            text=True, capture_output=True, check=False)
        if completed.returncode:
            raise RuntimeError(f"could not start sandbox: {completed.stderr.strip()}")
        return SandboxExecutor(completed.stdout.strip(), self.settings.command_timeout_seconds)

    @staticmethod
    def stop(executor: SandboxExecutor) -> None:
        subprocess.run(["docker", "stop", executor.container_id], text=True, capture_output=True, check=False)
