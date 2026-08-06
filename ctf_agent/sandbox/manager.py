from __future__ import annotations

import hashlib
import json
import subprocess
import uuid
from pathlib import Path

from ctf_agent.classifier import assert_safe_materials
from ctf_agent.config import Settings
from ctf_agent.sandbox.executor import SandboxExecutor
from ctf_agent.sandbox.planner import SandboxPlan

EGRESS_PROXY_HOST = "ctf-egress-proxy"


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

    @property
    def egress_proxy_image(self) -> str:
        source = self.project_root / "docker" / "egress_proxy.py"
        dockerfile = self.project_root / "docker" / "Dockerfile.egress-proxy"
        digest = hashlib.sha256(
            source.read_bytes() + dockerfile.read_bytes()
        ).hexdigest()
        return f"ctf-egress-proxy:{digest[:16]}"

    def ensure_image(self, plan: SandboxPlan) -> str:
        """Build only the selected capability set, and cache it by manifest hash."""
        image = self.image_for(plan)
        present = subprocess.run(
            ["docker", "image", "inspect", image],
            text=True,
            capture_output=True,
            check=False,
        )
        if present.returncode == 0:
            print(f"Using cached sandbox image: {image}", flush=True)
            return image
        print(f"Building sandbox image for: {', '.join(plan.capabilities)}", flush=True)
        completed = subprocess.run(
            [
                "docker",
                "build",
                "--build-arg",
                f"SANDBOX_CAPABILITIES={','.join(plan.capabilities)}",
                "--build-arg",
                f"SANDBOX_REVISION={self.build_fingerprint(plan)}",
                "-f",
                str(self.project_root / "docker" / "Dockerfile.sandbox"),
                "-t",
                image,
                str(self.project_root),
            ],
            text=True,
            check=False,
        )
        if completed.returncode:
            raise RuntimeError(
                f"sandbox image build exited with status {completed.returncode}"
            )
        return image

    def ensure_egress_proxy_image(self) -> str:
        image = self.egress_proxy_image
        present = subprocess.run(
            ["docker", "image", "inspect", image],
            text=True,
            capture_output=True,
            check=False,
        )
        if present.returncode == 0:
            return image
        completed = subprocess.run(
            [
                "docker",
                "build",
                "-f",
                str(self.project_root / "docker" / "Dockerfile.egress-proxy"),
                "-t",
                image,
                str(self.project_root),
            ],
            text=True,
            check=False,
        )
        if completed.returncode:
            raise RuntimeError(
                f"egress proxy image build exited with status {completed.returncode}"
            )
        return image

    def _start_egress_proxy(self, targets: tuple[str, ...]) -> tuple[str, str]:
        """Return a private network and its only egress-capable proxy container."""
        network = f"ctf-egress-{uuid.uuid4().hex[:16]}"
        created = subprocess.run(
            ["docker", "network", "create", "--internal", network],
            text=True,
            capture_output=True,
            check=False,
        )
        if created.returncode:
            raise RuntimeError(
                f"could not create private egress network: {created.stderr.strip()}"
            )
        proxy_name = f"ctf-egress-proxy-{uuid.uuid4().hex[:16]}"
        try:
            proxy = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-d",
                    "--name",
                    proxy_name,
                    "--network",
                    network,
                    "--network-alias",
                    EGRESS_PROXY_HOST,
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "64",
                    "--memory",
                    "128m",
                    "--tmpfs",
                    "/tmp:rw,nosuid,nodev,size=16m",
                    "-e",
                    f"EGRESS_TARGETS={json.dumps(targets)}",
                    self.ensure_egress_proxy_image(),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            if proxy.returncode:
                raise RuntimeError(
                    f"could not start egress proxy: {proxy.stderr.strip()}"
                )
            proxy_id = proxy.stdout.strip()
            attached = subprocess.run(
                ["docker", "network", "connect", "bridge", proxy_id],
                text=True,
                capture_output=True,
                check=False,
            )
            if attached.returncode:
                raise RuntimeError(
                    f"could not give egress proxy outbound access: {attached.stderr.strip()}"
                )
            return network, proxy_id
        except Exception:
            subprocess.run(
                ["docker", "stop", proxy_name],
                text=True,
                capture_output=True,
                check=False,
            )
            subprocess.run(
                ["docker", "network", "rm", network],
                text=True,
                capture_output=True,
                check=False,
            )
            raise

    def start(self, materials_dir: Path, plan: SandboxPlan) -> SandboxExecutor:
        assert_safe_materials(materials_dir)
        image = self.ensure_image(plan)
        egress_network: str | None = None
        egress_proxy_id: str | None = None
        if plan.network_enabled:
            egress_network, egress_proxy_id = self._start_egress_proxy(
                plan.network_targets
            )
            proxy_url = f"http://{EGRESS_PROXY_HOST}:3128"
            network_args = [
                "--network",
                egress_network,
                "-e",
                f"HTTP_PROXY={proxy_url}",
                "-e",
                f"HTTPS_PROXY={proxy_url}",
                "-e",
                f"http_proxy={proxy_url}",
                "-e",
                f"https_proxy={proxy_url}",
            ]
            network_label = "target-authorized proxy network"
        else:
            network_args = ["--network", "none"]
            network_label = "no-network"
        print(f"Starting isolated, {network_label} sandbox…", flush=True)
        completed = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-d",
                *network_args,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                str(self.settings.sandbox_pids_limit),
                "--memory",
                self.settings.sandbox_memory,
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=128m",
                "--user",
                "solver",
                "-v",
                f"{materials_dir.resolve()}:/materials:ro",
                "-w",
                "/tmp",
                image,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode:
            if egress_proxy_id:
                subprocess.run(
                    ["docker", "stop", egress_proxy_id],
                    text=True,
                    capture_output=True,
                    check=False,
                )
            if egress_network:
                subprocess.run(
                    ["docker", "network", "rm", egress_network],
                    text=True,
                    capture_output=True,
                    check=False,
                )
            raise RuntimeError(f"could not start sandbox: {completed.stderr.strip()}")
        return SandboxExecutor(
            completed.stdout.strip(),
            self.settings.command_timeout_seconds,
            egress_proxy_id=egress_proxy_id,
            egress_network=egress_network,
        )

    @staticmethod
    def stop(executor: SandboxExecutor) -> None:
        subprocess.run(
            ["docker", "stop", executor.container_id],
            text=True,
            capture_output=True,
            check=False,
        )
        if executor.egress_proxy_id:
            subprocess.run(
                ["docker", "stop", executor.egress_proxy_id],
                text=True,
                capture_output=True,
                check=False,
            )
        if executor.egress_network:
            subprocess.run(
                ["docker", "network", "rm", executor.egress_network],
                text=True,
                capture_output=True,
                check=False,
            )
