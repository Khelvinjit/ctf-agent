# CTF Agent — Implementation Plan

**Purpose:** Build a local, materials-first CTF solver. A user places a challenge description and its attachments in `challenge_materials/`; one AI agent identifies the challenge theme, chooses the smallest sandbox capability set that can plausibly solve it, then investigates the supplied files and prints a flag to the terminal.

**Scope:** This project solves authorised, local challenge material only. It does not log into CTF platforms, discover remote challenges, submit flags, or make network requests from the solver sandbox.

## 1. Product contract

### Input

```text
challenge_materials/
├── CHALLENGE_DESCRIPTION.md    # required
├── attachment.zip
└── nested/
    └── challenge.bin
```

`CHALLENGE_DESCRIPTION.md` contains the challenge statement. Every other file below `challenge_materials/` is available to the solver under the same relative path.

### Output

The command-line runner prints one of the following:

```text
FLAG: picoCTF{...}
```

or a clear failure result with the transcript path. It also stores the agent's classification, sandbox plan, commands, observations, and candidate flags in `logs/` for debugging.

## 2. Required solve flow

The order is intentional. The agent must understand the material before a sandbox image is selected or built.

1. **Inspect `challenge_materials/`.** Read the description and produce a safe inventory of filenames, sizes, file types, and archive members. Do not execute an attachment during this step.
2. **Decide the challenge theme.** The AI agent classifies the material (for example: web, crypto, forensics, reverse engineering, pwn, steganography, or misc) and records its confidence and evidence. It uses the complete pasted description and does not require headings, category labels, or any other template.
3. **Decide the sandbox contents.** From the theme and inventory, the agent returns a constrained capability plan: base utilities plus only the tools, language runtimes, and libraries needed for its first investigation. It should prefer a smaller profile when uncertain and request an additive expansion only when concrete evidence warrants it.
4. **Create the sandbox.** Build or select an image matching that plan, mount `challenge_materials/` read-only, create a separate writable working directory, and apply command and challenge time limits. Networking stays disabled unless a web challenge description explicitly supplies an HTTP(S) target; that target is recorded in the manifest.
5. **Solve from the supplied material.** Give the same agent the description, inventory, classification, sandbox capability list, and command tool. It iterates through inspection and analysis until it finds a valid flag or exhausts its budget.
6. **Validate and print.** Extract a value matching the configurable flag regex, print `FLAG: <value>` to stdout immediately, then write the transcript and a short writeup. There is no flag submission step for now.

## 3. Design constraints

- **One agent per challenge:** no model swarm or coordinator. The agent makes both the theme and sandbox decisions, then solves the challenge.
- **Local-only materials:** the runtime sandbox uses `--network none`; it sees only the mounted challenge directory and its own work area.
- **Minimal by default:** do not start every challenge with radare2, pwntools, Sage, volatility, and stego tools installed. Tooling is chosen because the materials justify it.
- **Expand, never guess broadly:** if the current sandbox cannot support a warranted next step, log the reason and add the smallest relevant capability. Re-run with preserved files and prior transcript.
- **Auditable decisions:** persist the theme decision and sandbox manifest before executing solver commands. A user should be able to see why a package entered the image.
- **No attachment execution on the host:** file identification and archive listings are non-executing; all untrusted analysis happens in the sandbox.

## 4. Sandbox capability profiles

Profiles are composable, not a single “full CTF image.” The planner should select a base plus zero or more additions.

| Capability | Typical evidence | Contents |
|---|---|---|
| `base` | every challenge | Python 3, shell coreutils, `file`, `strings`, `xxd`, `unzip`, `tar`, `jq` |
| `web` | HTML/JS, HTTP capture, web source, or an explicit challenge URL | `curl`, Python `requests`, HTML/JSON helpers; network remains disabled unless the description names an authorised URL |
| `crypto` | ciphertext, key material, encoding/cipher clues | `pycryptodome`, `gmpy2`, small Python analysis helpers |
| `forensics` | images, packet captures, disk files, metadata | `exiftool`, `binwalk`, `foremost`, selected image/PCAP utilities |
| `reverse` | ELF/PE/APK/WASM or bytecode | `binutils`, `gdb`, `radare2`, decompilation/disassembly helpers |
| `pwn` | exploitable native binary/source | `gdb`, `pwntools`, compiler/debugging libraries |
| `stego` | images/audio with hidden-data hints | `zsteg`, `steghide`, format-specific helpers |

The planner records exact packages/tools in a manifest such as `logs/manual/sandbox-plan.json`. An image cache may reuse an identical manifest; it must not silently substitute a broader profile.

## 5. Repository shape

```text
ctf_agent/
├── classifier.py             # inventory + agent theme decision
├── sandbox/
│   ├── planner.py            # maps decision to minimal capability manifest
│   ├── manager.py            # builds/selects image and starts isolated container
│   └── executor.py           # bounded command execution
├── solver/
│   ├── loop.py               # agent ↔ sandbox iteration
│   └── flag_extract.py       # regex/heuristic extraction
├── models/                   # configured AI client
└── writeup.py
scripts/
├── run_all.sh                # bootstrap then run local solve flow
└── solve_manual.py           # CLI entry point; prints the flag
challenge_materials/          # user-supplied challenge only
logs/                         # decisions, transcript, writeups
```

Existing skill retrieval may be used as compact optional context after classification. It must not replace inspecting the challenge material or force a broad sandbox profile.

## 6. Implementation phases

### Phase 0 — Local input contract

- Require `challenge_materials/CHALLENGE_DESCRIPTION.md`.
- Recursively inventory attachments without executing them; include type, size, hash, and archive member names where safe.
- Keep all paths relative to `challenge_materials/` and reject traversal/symlink escapes.

**Definition of done:** a run with a description and mixed attachments writes a stable inventory and performs no attachment execution on the host.

### Phase 1 — Theme classification

- Prompt the AI agent with the description and inventory to return structured JSON: `theme`, `confidence`, `evidence`, `initial_capabilities`, and `unknowns`.
- Validate the schema and save it before sandbox creation.
- Use a deterministic fallback classification of `misc` + `base` if the model response is malformed or unavailable.

**Definition of done:** representative crypto, web, reverse, and forensic fixtures yield a logged classification whose initial tool choices are appropriate and bounded.

### Phase 2 — Minimal sandbox planner and builder

- Turn the validated classification into an explicit capability manifest.
- Build/cache images keyed by that manifest, beginning with `base` and adding only requested capabilities.
- Run containers with no network by default, a read-only materials mount, a writable scratch mount, dropped privileges/capabilities where practical, and wall-clock limits. Enable network only for an explicit, manifest-recorded web target.
- Permit one controlled expansion path: the solver returns a structured reason and a small requested capability; the planner validates it and starts a replacement sandbox.

**Definition of done:** a web fixture starts with `base + web`, while a Caesar-cipher fixture starts with `base + crypto`; neither image contains unrelated reverse/pwn/forensic packages.

### Phase 3 — Solve loop

- Provide the agent the description, inventory, theme decision, sandbox manifest, flag regex, and a bounded `run_command` tool.
- Let it inspect and transform only supplied material and its scratch output.
- Detect matching flags after every response and command result; stop at the first validated match.
- Preserve the transcript across an approved sandbox expansion; temporary analysis files remain disposable inside the container.

**Definition of done:** a local easy challenge is classified, given a minimal sandbox, solved, and produces a matching flag without platform access.

### Phase 4 — CLI output and verification

- `./scripts/run_all.sh` bootstraps dependencies, runs classification → planning → sandbox → solve, and forwards the flag format option.
- Print `FLAG: <flag>` to stdout on success. Print errors and transcript locations to stderr on failure.
- Write `logs/manual/theme-decision.json`, `logs/manual/sandbox-plan.json`, `logs/manual/transcript.jsonl`, and a solved writeup.

**Definition of done:** an end-to-end fixture run emits the flag on stdout and all four records are inspectable.

## 7. Explicit non-goals for now

- CTFd/picoCTF adapters, browser automation, remote challenge discovery, and automatic flag submission.
- Parallel solving or sequential “model ladder” escalation.
- A universal, preinstalled full CTF tool image as the normal path.
- Network access from the solver sandbox.

These can be added later only if they preserve the local-materials-first contract and do not bypass the minimal-sandbox planning step.
