#!/usr/bin/env bash
# Run the pinned Veria Labs CTFd swarm integration.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM_DIR="$ROOT_DIR/integrations/verialabs-ctf-agent"
UV_BIN="${UV_BIN:-uv}"
build_image=false
allow_submit=false

usage() {
    cat <<'EOF'
Usage:
  ./scripts/run_veria_ctf_agent.sh [--build] [--submit] [--] [ctf-solve options]

Runs the pinned upstream Veria Labs multi-model CTFd solver. Flags are never
submitted unless --submit is supplied. All remaining arguments are forwarded to
the upstream ctf-solve command.

Examples:
  ./scripts/run_veria_ctf_agent.sh --build -- --coordinator codex \
    --models codex/gpt-5.4-mini --max-challenges 3

  ./scripts/run_veria_ctf_agent.sh --submit -- --challenge challenges/example

Environment:
  CTFD_URL, CTFD_TOKEN, ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY
  VERIA_SANDBOX_IMAGE   Docker image name; defaults to ctf-sandbox.
  UV_BIN                uv executable; defaults to uv.
EOF
}

while (($#)); do
    case "$1" in
        --build)
            build_image=true
            shift
            ;;
        --submit)
            allow_submit=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            break
            ;;
    esac
done

if [[ ! -f "$UPSTREAM_DIR/pyproject.toml" ]]; then
    echo "The Veria CTF agent submodule is not initialized." >&2
    echo "Run: git submodule update --init --recursive" >&2
    exit 1
fi

command -v "$UV_BIN" >/dev/null || {
    echo "uv is required but was not found on PATH." >&2
    exit 1
}

image_name="${VERIA_SANDBOX_IMAGE:-ctf-sandbox}"
solver_args=("$@")
if [[ -n "${VERIA_SANDBOX_IMAGE:-}" ]]; then
    solver_args=(--image "$image_name" "${solver_args[@]}")
fi

if [[ "$build_image" == true ]]; then
    command -v docker >/dev/null || {
        echo "Docker is required to build the Veria sandbox image." >&2
        exit 1
    }
    echo "Building Veria sandbox image: $image_name"
    docker build -f "$UPSTREAM_DIR/sandbox/Dockerfile.sandbox" -t "$image_name" "$UPSTREAM_DIR"
fi

if [[ "$allow_submit" == false ]]; then
    echo "Dry run: CTFd flag submission is disabled. Pass --submit to enable it."
    solver_args=(--no-submit "${solver_args[@]}")
else
    echo "Live mode: CTFd flag submission is enabled."
fi

exec "$UV_BIN" --directory "$UPSTREAM_DIR" run ctf-solve "${solver_args[@]}"
