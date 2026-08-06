# CTF Agent — Architecture & Strategy Overview

> For the implementation sequence and acceptance checks, see [PLAN.md](PLAN.md).

## What this is

A local CTF challenge solver for authorised material. Put a challenge description and any attachments in `challenge_materials/`, run the launcher, and the project uses one AI agent to:

1. decide what kind of challenge it is;
2. decide the smallest sandbox it needs;
3. analyse and solve the supplied material; and
4. print the flag in the terminal.

There is no platform login, challenge discovery, browser automation, network solving, or flag submission in this version.

## The core loop

```text
challenge_materials/
       │
       ▼
safe inventory + description
       │
       ▼
AI agent: classify theme and explain evidence
       │
       ▼
AI agent: request the minimum capabilities needed
       │
       ▼
isolated sandbox built from that manifest
       │
       ▼
AI agent: inspect files and run bounded analysis commands
       │
       ▼
FLAG: <flag>   (printed to terminal)
```

## Why the sandbox comes after classification

CTF tooling is broad and heavy. A Caesar cipher does not need a reverse-engineering suite; an image metadata puzzle does not need a compiler and pwntools. Starting with every possible tool increases image build time, attack surface, and agent distraction.

The agent first sees only non-executing information: the written prompt, filenames, file types, sizes, and safe archive listings. From that evidence it records a theme and a small capability manifest. The sandbox is then created only with the relevant base utilities and additions. If solving reveals a specific missing need, the agent can request a narrowly scoped expansion, which is logged before use.

## Main components

| Component | Responsibility |
|---|---|
| Material inventory | Safely describes everything under `challenge_materials/` without executing untrusted attachments on the host. |
| Theme classifier | Uses the AI agent to identify the likely challenge class and justify the decision. |
| Sandbox planner | Converts the classification into an auditable, minimal list of tools and runtimes. |
| Sandbox manager | Runs the selected image with no network by default, read-only challenge materials, writable scratch space, and time limits. An explicit web challenge URL enables target-authorised access for that run. |
| Solver loop | Lets the same agent inspect files and run commands until it extracts a flag or gives a useful failure reason. |
| CLI/logging | Prints the flag now; keeps decisions and the transcript for review. |

## Lightweight capability sets

Every sandbox receives a small `base` layer: Python, shell utilities, `file`, `strings`, `xxd`, and archive tools. The planner then adds only what the evidence supports:

- `web` for local web source or HTTP artefacts
- `crypto` for ciphers, encoded data, or key material
- `forensics` for media, disk, or packet artefacts
- `reverse` for executable or bytecode analysis
- `pwn` for native exploitation work
- `stego` for hidden-data challenges

The plan lists the exact capabilities and tools. An identical plan may reuse a cached image, but the runner must not quietly switch to a larger “everything installed” image.

## Safety boundary

Challenge attachments are untrusted. The host does only safe inventory work. The solver runs inside a container with networking disabled by default, a read-only mount of `challenge_materials/`, a separate writable working directory, and command/challenge timeouts. For a web challenge with an explicit URL in the description, that URL is treated as authorised target input and is recorded in the sandbox manifest; other network targets remain denied by the solver.

## What a run produces

On success, the important visible result is:

```text
FLAG: picoCTF{example}
```

The runner also records the classification decision, sandbox manifest, model/tool transcript, and a short writeup in `logs/`. On failure it reports the transcript location rather than pretending to have solved the challenge.

## Success criteria

The project is successful when a user can add a new local challenge to `challenge_materials/`, run one command, and see a valid flag printed to the terminal—while the logs make it clear which theme the agent chose and why only the selected sandbox tools were installed.
