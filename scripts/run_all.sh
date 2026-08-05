#!/usr/bin/env bash
# Bootstrap this project and solve the material supplied in challenge_materials/.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv}"
PYTHON_BIN="${PYTHON_BIN:-python}"
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    cat <<'EOF'
Usage:
  ./scripts/run_all.sh [scripts/solve_manual.py options]

Required input layout:
  challenge_materials/
  ├── CHALLENGE_DESCRIPTION.md
  └── ...all other challenge files and directories...

Environment:
  PYTHON_BIN=python       Python used to create the virtual environment.
  VENV_DIR=.venv          Location of the virtual environment.
  CTF_SKILLS_DIR=/path    Optional local ljagiello/ctf-skills checkout to index.
  SANDBOX_IMAGE=ctf-sandbox  Prefix for images cached by sandbox manifest.
EOF
    exit 0
fi

command -v "$PYTHON_BIN" >/dev/null || {
  echo "Python executable not found: $PYTHON_BIN" >&2
  exit 1
}
command -v docker >/dev/null || {
  echo "Docker is required but was not found on PATH." >&2
  exit 1
}
docker info >/dev/null 2>&1 || {
  echo "Docker is installed but its daemon is unavailable. Start Docker Desktop and retry." >&2
  exit 1
}

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -e "$ROOT_DIR[dev]"

if [[ -n "${CTF_SKILLS_DIR:-}" ]]; then
  if [[ ! -f "$CTF_SKILLS_DIR/SKILL.md" ]] && ! find "$CTF_SKILLS_DIR" -name SKILL.md -print -quit | grep -q .; then
    echo "CTF_SKILLS_DIR does not contain any SKILL.md files: $CTF_SKILLS_DIR" >&2
    exit 1
  fi
  "$VENV_DIR/bin/python" -m ctf_agent.skills.build_index "$CTF_SKILLS_DIR"
fi

exec "$VENV_DIR/bin/python" "$ROOT_DIR/scripts/solve_manual.py" "$@"
