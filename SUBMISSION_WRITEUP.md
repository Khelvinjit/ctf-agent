# CTF Agent — Submission Write-up

## Overview

CTF Agent is an LLM harness for solving **authorised CTF challenges** from a supplied prompt and files. It is designed around one principle: **classify the evidence before building the sandbox**. The agent first performs safe triage, then receives only the tools needed for the likely challenge type, and finally investigates in an isolated Docker environment.

The result is a controlled, reproducible solve process that prints `FLAG: <verified value>` only after evidence supports it and records the decisions, commands, and model handoffs for review.

For the supplied ModelHub challenge, the declared URL and `POST /upload` → `POST /infer` flow are treated as authorised investigation input. The harness permits access only to that explicit target through an allow-listed proxy; it does not claim an unverified exploit or flag.

## Agent harness architecture

```text
Challenge description + attachments
              │
              ▼
Safe inventory (no host-side execution)
              │
              ▼
LLM triage: theme + evidence + minimal capabilities
              │
              ▼
Sandbox plan → isolated Docker container
              │
              ▼
LLM tool loop: inspect → hypothesise → verify
              │
              ▼
Verified flag + auditable logs/write-up
```

### Main components

| Component | Purpose |
|---|---|
| `classifier.py` | Inventories files, rejects symlinks, extracts explicit target URLs, and asks the LLM to classify the challenge. |
| `sandbox/planner.py` | Produces an explicit, minimal capability manifest and rejects unrelated expansions. |
| `sandbox/manager.py` | Builds a manifest-specific Docker image and runs the hardened container. |
| `solver/loop.py` | Provides bounded command execution, local technique lookup, flag validation, and controlled capability expansion. |
| `models/client.py` | Normalises Gemini, Groq, and OpenRouter model/function-calling APIs and handles fallback routes. |
| `handoff.py` | Creates compact evidence briefs for a replacement model or resumed run. |
| `solve_manual.py` | Orchestrates the full intake → classify → plan → solve workflow. |

## Implementation approach

1. **Safe intake.** The runner reads `CHALLENGE_DESCRIPTION.md` and inventories attachments by path, size, SHA-256, file type, and archive-member names. It does not extract or execute untrusted files on the host.
2. **LLM classification.** The LLM returns a structured challenge theme (`web`, `crypto`, `forensics`, `reverse`, `pwn`, `stego`, or `misc`) and evidence. It then chooses at most two initial capability profiles.
3. **Minimal sandbox.** Every image has only a small base layer plus selected tools. Images are keyed by the exact manifest, making a run reproducible and cacheable.
4. **Bounded solving.** The LLM uses function tools to issue targeted sandbox commands, retrieve optional local technique snippets, or request one evidence-backed capability expansion. Commands, output size, model turns, and total challenge time are limited.
5. **Verification and logs.** Flag-shaped values are extracted from model output and tool output; placeholders are rejected. The run saves a theme decision, sandbox plan, JSONL transcript, Markdown handoff, and solved write-up.

## Capability profiles

| Profile | Selected tools |
|---|---|
| Base | Python, shell tools, `file`, `strings`, `xxd`, archive tools, `jq` |
| Web | `curl`, Python `requests` |
| Crypto | `pycryptodome`, `gmpy2` |
| Forensics | `exiftool`, `binwalk`, `foremost`, `tshark` |
| Reverse | `binutils`, `gdb`, `radare2` |
| Pwn | `pwntools`, `ROPgadget`, compiler/debugging tools |
| Stego | `steghide`, `zsteg` |

The planner starts small: for example, a cipher task gets crypto tools rather than reverse-engineering tools. A capability can be added only if it is compatible with the classified theme and backed by solver evidence.

## Design and security decisions

| Decision | Benefit |
|---|---|
| Classify before building | Avoids an expensive, broad “all tools” image. |
| One coherent LLM agent | Preserves investigation context without a costly swarm. |
| Read-only materials and disposable `/tmp` | Keeps supplied files immutable and analysis temporary. |
| Non-root Docker runtime | Runs as `solver`, with dropped Linux capabilities and `no-new-privileges`. |
| Resource limits | Enforces memory, PID, command, and challenge deadlines. |
| Network disabled by default | Prevents accidental host or internet discovery. |
| Explicit-target egress proxy | Allows only the URL written in the challenge statement; private, loopback, and undeclared targets are blocked. |
| Evidence handoffs + fingerprinted resume | Enables provider rotation and restart recovery without mixing evidence from different challenges. |

## Technology stack

| Area | Technologies |
|---|---|
| Language and runtime | Python 3.11+, Bash, `venv`, pip, Hatchling |
| Isolation | Docker, Dockerfile v1.7, Ubuntu 24.04 |
| LLMs / APIs | Google Gemini `generateContent`; Groq and OpenRouter OpenAI-compatible chat APIs; function calling |
| Default configured routes | Gemini `gemini-3.6-flash`; Groq `openai/gpt-oss-120b`; OpenRouter `openrouter/free` (all configurable) |
| Python libraries | `httpx`, `pydantic-settings`, `python-dotenv`, `rich`, `pytest`, `pytest-asyncio` |
| Retrieval and logging | SQLite full-text search, JSON/JSONL, Markdown |
| Optional CTF integration | Local `ctf-skills` retrieval index and isolated Veria Labs CTFd swarm integration |

## Run and outputs

```sh
./scripts/run_all.sh
```

On success, the CLI prints `FLAG: <value>`. Reviewable artefacts are written to:

```text
logs/manual/theme-decision.json
logs/manual/sandbox-plan.json
logs/manual/transcript.jsonl
logs/manual/handoff.md
logs/writeups/manual.md
```

This provides a capable CTF-solving workflow without treating the model as trusted or granting it a broad, opaque execution environment.
