# CTF Agent

A local, materials-first solver for authorised CTF challenges. It inventories the supplied files without executing them on the host, asks one configured AI model to classify the challenge and select the smallest useful sandbox, then solves from those files and prints the flag.

## Run a challenge

Copy `.env.example` to `.env` and configure one model provider:

```text
GEMINI_API_KEY=...
# Add as many numbered Gemini keys as needed. They are tried in numeric order
# after a Gemini quota response, before the non-Gemini fallback routes.
GEMINI_API_KEY1=...
GEMINI_API_KEY2=...
MODEL_PROVIDER=gemini
MODEL_NAME=gemini-3.6-flash
# Optional fallback routes; routes without a key are skipped.
GROQ_API_KEY=...
OPENROUTER_API_KEY=...
MODEL_ROTATION=gemini:gemini-3.6-flash,groq:openai/gpt-oss-120b,openrouter:openrouter/free
```

The runner tries `GEMINI_API_KEY` (if set) and every `GEMINI_API_KEY<n>` in
numeric order. When Gemini reports a quota/rate limit, that key is retired for
the rest of the run and the next Gemini key is used. Only after every configured
Gemini key is limited does it move to the configured Groq or OpenRouter routes.
It also rotates routes when a model is unavailable or uses its `MAX_ITERATIONS`
response budget. Each replacement model receives the full prior evidence and
tool history. Set `MODEL_PROVIDER` and `MODEL_NAME` to choose the first route;
routes without a configured key are skipped. Then add the authorised material:

```text
challenge_materials/
├── CHALLENGE_DESCRIPTION.md
├── attachment.zip
└── nested/
    └── challenge.bin
```

The description file is required, but its contents have no required format: paste the challenge statement exactly as supplied, including prose, URLs, code, and any copied metadata. The first non-empty line is used only as a display title; the agent classifies the actual text and material itself. Run:

```sh
./scripts/run_all.sh
```

On success, the runner writes `FLAG: <value>` to stdout. It stores the classification in `logs/manual/theme-decision.json`, the exact sandbox manifest in `logs/manual/sandbox-plan.json`, a JSONL transcript, and a writeup. Temporary files are held only in the container's discarded `/tmp` filesystem.

`MODEL_ROTATION` in `.env.example` includes Gemini free-tier routes and
OpenRouter `:free` variants. These models remain subject to provider limits, so
the final `openrouter/free` route automatically selects a compatible free model
when a named route is unavailable.

## Model and run handoffs

When a model reaches its turn budget, the next route receives a compact handoff
brief containing the latest assessments, commands, outputs, sandbox scope, and a
single next-step instruction. The same brief is continuously written to
`logs/manual/handoff.md` beside the JSONL transcript. If you relaunch the solver
with exactly the same description and material inventory, it resumes from that
evidence; changing either starts a new session and prevents stale findings from
leaking into a different challenge.

## Sandboxing

The model first sees only the description and a safe inventory of filenames, MIME types, hashes, sizes, and archive member names. It chooses a theme (`web`, `crypto`, `forensics`, `reverse`, `pwn`, `stego`, or `misc`) and no more than two capabilities for an initial investigation. The runner builds and caches a Docker image keyed to that manifest.

At runtime, the container has no Linux capabilities, a read-only `/materials` mount, a disposable writable `/tmp` filesystem, process and memory limits, and command/challenge timeouts. It runs with no network by default. A web challenge whose description explicitly supplies an HTTP(S) URL is attached only to a private network and reaches the declared host and port through an allow-list proxy; private, loopback, and undeclared destinations are rejected. Before the solver receives a model turn, the runner makes one proxy-routed request to each declared target. If a target is unreachable, the run stops with a logged infrastructure diagnosis instead of spending model turns on connectivity retries. Symlinks in `challenge_materials/` are rejected before the directory is mounted. The agent may request one logged, theme-compatible capability expansion if the first sandbox produces concrete evidence that it is needed.

This version does not log into a CTF platform, discover remote challenges, or submit flags. A URL explicitly included in an authorised web challenge description is the exception: it is treated as the target for that one sandboxed solve.

## Veria Labs CTFd swarm integration

The local-material solver above remains the default. For a live, authorised CTFd
competition, the pinned [Veria Labs CTF agent](https://github.com/verialabs/ctf-agent)
is included as the `integrations/verialabs-ctf-agent` submodule. It is kept
isolated because it has a different dependency stack (Python 3.14+), coordinates
multiple model solvers, and can submit flags to CTFd.

Initialise the submodule after cloning this repository, then create separate
credentials for the swarm:

```sh
git submodule update --init --recursive
cp .env.veria.example .env.veria
# Edit .env.veria, then export it only for this command.
set -a; source .env.veria; set +a
```

Build the upstream sandbox image and run a dry-run coordinator (the default):

```sh
./scripts/run_veria_ctf_agent.sh --build -- --coordinator codex \
  --models codex/gpt-5.4-mini --max-challenges 3
```

The wrapper forwards all remaining options to upstream `ctf-solve` and adds
`--no-submit` unless you explicitly pass `--submit`. Use `--submit` only when
flag submission to the configured authorised CTFd instance is intended.

## Optional technique index

Set `CTF_SKILLS_DIR` to a local `ljagiello/ctf-skills` checkout before launching to build the compact local retrieval index:

```sh
CTF_SKILLS_DIR=/path/to/ctf-skills ./scripts/run_all.sh
```

The index is optional and does not control sandbox selection; it only gives the solver compact, relevant technique hints after classification.
