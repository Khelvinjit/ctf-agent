# CTF Agent — Solution Write-up and Technical Documentation

## 1. Executive summary

This project is an AI-assisted harness for solving **authorised CTF challenges**. It starts from a pasted challenge statement and supplied files, performs non-executing triage, selects the smallest practical analysis environment, and gives an LLM a bounded tool loop inside that environment. The goal is a reproducible result—`FLAG: <value>`—with the reasoning, sandbox plan, commands, and model handoffs recorded for review.

The central design choice is **classify before building the sandbox**. Rather than starting every task in a large, general-purpose CTF image, the agent first determines the likely challenge theme and chooses a small set of capabilities. This reduces setup time, attack surface, and irrelevant tool distraction.

For the provided challenge prompt, the URL `http://52.76.96.108:3015/` is treated as explicitly authorised challenge input. The harness recognises it during triage, selects web capability as needed, and permits access only through an allow-listed egress proxy. The documented API shape—`POST /upload` followed by `POST /infer`—is given to the solver as part of the challenge description. This write-up describes the implemented solver architecture; it does not claim a flag that has not been independently verified by a run.

## 2. Problem and requirements addressed

The harness addresses the following practical CTF-agent requirements:

| Requirement | Implemented approach |
|---|---|
| Solve authorised challenge materials | The runner takes `challenge_materials/CHALLENGE_DESCRIPTION.md` plus attachments and works only within that scope. |
| Support mixed challenge categories | Theme classification supports `web`, `crypto`, `forensics`, `reverse`, `pwn`, `stego`, and `misc`. |
| Avoid executing untrusted inputs on the host | Host-side triage records paths, hashes, file types, sizes, and archive member names only; attachments are analysed in Docker. |
| Use an LLM agent effectively | The agent receives the challenge context, a minimal tool list, function tools, bounded terminal output, and category-specific operating guidance. |
| Keep analysis controlled and reproducible | The sandbox manifest is persisted and used as part of the Docker image cache key. |
| Support an authorised live web target | Only HTTP(S) URLs explicitly present in the description are reachable, through a proxy that rejects all other destinations. |
| Continue after model limits or a restart | Evidence is compacted into a handoff, model routes can rotate, and a matching challenge fingerprint permits resume. |
| Produce auditable output | Theme decision, sandbox plan, JSONL transcript, handoff, and final write-up are stored in `logs/`. |

## 3. Agent harness architecture

```text
                        Authorised inputs
              ┌────────────────────────────────┐
              │ challenge description + files   │
              └───────────────┬────────────────┘
                              │
                Safe host-side inventory only
                              │
                              ▼
              ┌────────────────────────────────┐
              │ LLM triage                      │
              │ • classify CTF theme            │
              │ • explain evidence              │
              │ • request 0–2 initial skills    │
              └───────────────┬────────────────┘
                              │
                              ▼
              ┌────────────────────────────────┐
              │ Sandbox planner                 │
              │ base + minimal compatible tools │
              │ manifest + image fingerprint    │
              └───────────────┬────────────────┘
                              │
                              ▼
              ┌────────────────────────────────┐
              │ Isolated Docker sandbox         │
              │ read-only /materials, /tmp      │
              │ no network by default           │
              └───────────────┬────────────────┘
                              │  bounded tool calls
                              ▼
              ┌────────────────────────────────┐
              │ LLM solver loop                 │
              │ inspect → hypothesise → verify  │
              │ optional local skill retrieval  │
              └───────┬───────────────┬────────┘
                      │               │
             verified flag       missing evidence
                      │               │
                      ▼               ▼
            FLAG: <value>   one validated expansion
                              or model handoff/rotation
```

### Components

| Component | Responsibility |
|---|---|
| `ctf_agent/classifier.py` | Recursively inventories the supplied materials, rejects symlinks, extracts explicit HTTP(S) URLs, and asks the model for a structured theme decision. |
| `ctf_agent/sandbox/planner.py` | Converts the decision into an explicit, theme-compatible capability manifest; prevents unrelated expansion. |
| `ctf_agent/sandbox/manager.py` | Builds/caches the corresponding Docker image and starts the hardened sandbox. |
| `ctf_agent/sandbox/executor.py` | Executes bounded commands in the running container and performs authorised-target preflight checks. |
| `ctf_agent/solver/loop.py` | Implements the agent/tool loop, output truncation, command policy, flag extraction, expansion requests, time limits, and model handoffs. |
| `ctf_agent/models/client.py` | Normalises Gemini, Groq, and OpenRouter chat/function-calling APIs and handles provider/key rotation. |
| `ctf_agent/handoff.py` | Produces a compact evidence brief for the next model or a resumed session. |
| `ctf_agent/skills/` | Optionally indexes a local CTF technique library in SQLite FTS and retrieves compact, category-relevant hints. |
| `scripts/solve_manual.py` | Orchestrates inventory → classify → plan → sandbox → solve → write logs. |

## 4. End-to-end implementation approach

### Phase A — Safe intake and evidence gathering

1. The runner requires `challenge_materials/CHALLENGE_DESCRIPTION.md` and reads its complete contents; no specific heading format is needed.
2. It inventories every other material file without executing it. Each record contains the relative path, byte size, SHA-256, type reported by `file`, and archive member names where applicable.
3. Symlinks are rejected so the materials mount cannot expose files outside the authorised input directory.
4. Explicit HTTP(S) URLs are extracted from the supplied description. They are treated as declared, auditable target input rather than as an opportunity for open internet access.

### Phase B — LLM theme classification and minimal planning

The model first receives only the written description and safe inventory. It must return structured JSON with a theme, confidence, evidence, and unknowns. A second constrained prompt asks for zero to two initial capabilities. Invalid or unavailable model responses fall back to a conservative keyword-based classification.

The planner always includes the `base` capability and allows additions only when they match the classified theme. For example, a crypto task can receive `crypto`; a pwn task can receive `pwn` and `reverse`; a forensics task may add `stego`. An explicitly declared web URL can add the narrowly scoped `web` capability alongside another theme.

### Phase C — Reproducible, least-privilege sandbox

The Docker image is derived from the exact manifest, and its cache key includes both the manifest and Dockerfile contents. The runtime container is configured with:

- read-only root filesystem and read-only `/materials` mount;
- disposable writable `/tmp` only;
- non-root `solver` user;
- all Linux capabilities dropped and `no-new-privileges` enabled;
- PID and memory limits;
- per-command and whole-challenge timeouts; and
- no network by default.

For an explicit challenge URL, the runner creates a private Docker network. The solver container can access only a dedicated HTTP(S) proxy; that proxy is configured with the declared target host and port and rejects loopback, private, undeclared, or otherwise disallowed destinations. The target is preflighted before model turns are spent, allowing infrastructure failures to be reported immediately.

### Phase D — Bounded solve loop

The solver receives the challenge context, classification, sandbox plan, flag regex, any local technique hints, and three function tools:

| Tool | Purpose | Guardrail |
|---|---|---|
| `run_command` | Run a targeted shell command inside the sandbox. | Commands are limited to the sandbox scope, time-bounded, and have output excerpts capped while preserving useful beginning/end context. |
| `search_more_techniques` | Retrieve a small number of relevant local CTF snippets. | Optional local SQLite index; never replaces direct inspection of the materials. |
| `request_sandbox_expansion` | Request a missing capability with supporting evidence. | Only one expansion is permitted by default, and the planner rejects capabilities incompatible with the classified theme. |

The loop detects a candidate matching the configured flag regex after model responses and command outputs. Placeholder/template values are rejected. On a verified match it stops, prints the flag, and saves an artefact-backed write-up.

### Phase E — Resilience and audit trail

To control cost and improve recovery, the project has a configurable iteration budget and a model-route list. Gemini keys are used in numeric order and retired after quota responses; the client can then rotate to configured Groq or OpenRouter routes. Each incoming model gets a compact handoff containing recent assessments, commands, outputs, sandbox scope, and a next-step instruction.

The runner fingerprints the complete description and material inventory. It resumes only if that fingerprint matches the previous run, avoiding evidence leakage between challenges.

## 5. Capability profiles

| Capability | Typical evidence | Main tools installed |
|---|---|---|
| `base` | Every task | Python 3, shell/core utilities, `file`, `strings`, `xxd`, `unzip`, `tar`, `jq` |
| `web` | HTML/JS, HTTP artefacts, or explicit target URL | `curl`, Python `requests` |
| `crypto` | Ciphertext, key material, encoding/cipher clues | `pycryptodome`, `gmpy2` |
| `forensics` | Images, packet captures, disks, metadata | `exiftool`, `binwalk`, `foremost`, `tshark` |
| `reverse` | ELF/PE/APK/WASM/bytecode | `binutils`, `gdb`, `radare2` |
| `pwn` | Native binary/source exploitation | `pwntools`, `ROPgadget`, compiler/debugging tools |
| `stego` | Hidden data in media | `steghide`, `zsteg` |

This composable design avoids a universal tool image. For example, a Caesar-cipher task does not carry reverse-engineering tools, and an image metadata task does not need a compiler or pwntools.

## 6. Design decisions and rationale

| Decision | Why it matters |
|---|---|
| One agent for classification, planning, and solving | Preserves context and keeps the harness economical; the model owns a coherent investigation rather than coordinating a large swarm. |
| Classify before sandbox creation | Reduces image build cost, attack surface, and irrelevant tools. |
| Separate planning from executing | A theme decision and an auditable manifest exist before any solver command is run. |
| Additive expansion only | The agent must produce concrete evidence for a small missing capability; it cannot jump straight to an all-tools image. |
| Deny network by default | CTF attachments and model-generated commands cannot silently probe the host or internet. |
| Explicit-target proxy, not broad egress | A live challenge URL remains usable while preventing pivoting to arbitrary/internal services. |
| Preserve complete tool exchanges during compaction | The model keeps command/result pairs together, avoiding a continuation that lacks the evidence for a previous action. |
| Save structured JSONL and Markdown evidence | Makes decisions inspectable, supports debugging, and enables reliable recovery after an interrupted run. |
| Validate flags rather than trusting prose | Prevents the model from returning a source-code placeholder or unsupported candidate as a solution. |

## 7. Challenge-specific handling: OpenAI × Hugging Face attack

The supplied challenge statement contains the clue “OpenAI x Huggingface attack,” a ModelHub inference service, a declared target URL, and these endpoints:

```text
POST /upload  {"data": ...}
POST /infer   {"id": ...}
```

The harness treats these details as investigation hypotheses, not as a pre-asserted exploit. During a live run it:

1. records the entire prompt and authorised URL in the sandbox plan;
2. attaches the `web` capability through the restricted egress path;
3. preflights the declared service before allocating model iterations;
4. lets the solver inspect endpoint behaviour and upload/inference handling from inside the sandbox; and
5. requires observable evidence for any final flag.

This is deliberately safer and more reproducible than granting the agent general network access or assuming a payload strategy from the clue alone.

## 8. Technology stack

### Languages, runtime, and packaging

| Technology | Role |
|---|---|
| Python 3.11+ | Primary implementation language for orchestration, model clients, sandbox control, logging, and tests. |
| Hatchling / `pyproject.toml` | Python package build configuration. |
| `venv` + `pip` | Local project bootstrap in `scripts/run_all.sh`. |
| Bash | CLI launcher scripts. |
| Docker / Dockerfile syntax v1.7 | Reproducible capability-specific images and isolated runtime containers. |
| Ubuntu 24.04 | Base operating system for sandbox images. |

### LLMs and model APIs

| Provider/API | How it is used |
|---|---|
| Google Gemini `generateContent` REST API | Default configurable route; supports a rotating pool of Gemini API keys. The repository default is `gemini-3.6-flash` as configured in `ctf_agent/config.py`. |
| Groq OpenAI-compatible Chat Completions API | Optional fallback route; default configuration names `openai/gpt-oss-120b`. |
| OpenRouter OpenAI-compatible Chat Completions API | Optional fallback route; supports named/free routing, with `openrouter/free` configured by default. |
| OpenAI-style function calling | Internal abstraction used for model-directed commands, local technique retrieval, and sandbox expansion requests. |

Model providers and model names are configurable through environment variables. A run should report the actual selected route from its log rather than assuming a particular provider was used.

### Python libraries

| Library | Role |
|---|---|
| `httpx` | HTTP client for LLM-provider APIs. |
| `pydantic-settings` | Typed environment/.env configuration. |
| `python-dotenv` | `.env` loading support. |
| `rich` | CLI presentation dependency. |
| `pytest`, `pytest-asyncio` | Automated test suite. |
| Standard library: `sqlite3` FTS | Optional local CTF technique retrieval index. |
| Sandbox-only: `pycryptodome`, `gmpy2`, `pwntools`, `ROPgadget`, `requests` | Installed only when their selected capability requires them. |

### Sandbox and analysis tooling

The base sandbox includes Python, shell utilities, `file`, `strings`, `xxd`, archive tools, and `jq`. Optional profiles install only the relevant web, crypto, forensics, reverse, pwn, or steganography packages listed in Section 5. The live-target proxy is a small Python service built from `docker/egress_proxy.py`.

### Integrated optional tooling

| Integration | Role |
|---|---|
| Local `ljagiello/ctf-skills` checkout | Optional source for compact, searchable technique hints (`CTF_SKILLS_DIR`). |
| Veria Labs CTF agent submodule | Optional, isolated CTFd swarm integration for an authorised live competition; invoked by `scripts/run_veria_ctf_agent.sh`, dry-run/no-submit by default. |

## 9. Running the solution

1. Place the full challenge statement in `challenge_materials/CHALLENGE_DESCRIPTION.md` and place all authorised attachments beside it.
2. Copy `.env.example` to `.env` and configure at least one model provider/key.
3. Ensure Docker Desktop/daemon is running.
4. Execute:

```sh
./scripts/run_all.sh
```

5. Inspect the result and audit artefacts:

```text
FLAG: <verified value>
logs/manual/theme-decision.json
logs/manual/sandbox-plan.json
logs/manual/transcript.jsonl
logs/manual/handoff.md
logs/writeups/manual.md
```

## 10. Verification strategy

The test suite exercises the core safety and continuity properties, including:

- archive inventory without extraction and symlink rejection;
- bounded theme-to-capability planning and rejected unrelated expansions;
- explicit URL allow-list planning;
- flag extraction that rejects placeholders;
- tool-result continuity across model turns;
- route rotation and handoff evidence;
- transcript resilience to partial JSONL writes;
- challenge-fingerprint-gated resume;
- output compaction that retains both useful ends; and
- Gemini/OpenAI-compatible tool-call serialisation and key-pool rotation.

Run the tests with:

```sh
python -m pytest
```

## 11. Limitations and next steps

- The local solver remains oriented to explicitly authorised inputs; it does not discover targets or submit flags automatically.
- A live web service can change or become unavailable; the preflight is designed to distinguish infrastructure failure from a failed solve hypothesis.
- Model quality and provider quotas still influence solve performance. The route rotation and handoff system improves continuity but does not guarantee a solve.
- The default limit is one sandbox expansion. This intentionally favours predictable resource use; it can be made configurable for more complex authorised challenges.
- Future work could add benchmark fixtures, evaluation metrics such as solve rate/cost/time, and richer adversarial-input tests while preserving the least-privilege planning contract.

## 12. Deliverables

- This document: architecture, solution approach, security decisions, and full technology stack.
- `NOTEBOOKLM_MINIMAL_SLIDES.md`: a ready-to-paste instruction brief for generating a concise, minimal slide deck.
- Source code and tests implementing the described harness.
