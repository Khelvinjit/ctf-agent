# CTF Agent

A local, materials-first solver for authorised CTF challenges. It inventories the supplied files without executing them on the host, asks one configured AI model to classify the challenge and select the smallest useful sandbox, then solves from those files and prints the flag.

## Run a challenge

Copy `.env.example` to `.env` and configure one model provider:

```text
GEMINI_API_KEY=...
MODEL_PROVIDER=gemini
MODEL_NAME=gemini-2.5-flash
```

Alternatively set `OPENROUTER_API_KEY` and `MODEL_PROVIDER=openrouter`. Then add the authorised material:

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

## Sandboxing

The model first sees only the description and a safe inventory of filenames, MIME types, hashes, sizes, and archive member names. It chooses a theme (`web`, `crypto`, `forensics`, `reverse`, `pwn`, `stego`, or `misc`) and no more than two capabilities for an initial investigation. The runner builds and caches a Docker image keyed to that manifest.

At runtime, the container has no Linux capabilities, a read-only `/materials` mount, a disposable writable `/tmp` filesystem, process and memory limits, and command/challenge timeouts. It runs with no network by default. A web challenge whose description explicitly supplies an HTTP(S) URL receives network access for that run so it can analyse that authorised target; the solver rejects commands for any other URL. Symlinks in `challenge_materials/` are rejected before the directory is mounted. The agent may request one logged, theme-compatible capability expansion if the first sandbox produces concrete evidence that it is needed.

This version does not log into a CTF platform, discover remote challenges, or submit flags. A URL explicitly included in an authorised web challenge description is the exception: it is treated as the target for that one sandboxed solve.

## Optional technique index

Set `CTF_SKILLS_DIR` to a local `ljagiello/ctf-skills` checkout before launching to build the compact local retrieval index:

```sh
CTF_SKILLS_DIR=/path/to/ctf-skills ./scripts/run_all.sh
```

The index is optional and does not control sandbox selection; it only gives the solver compact, relevant technique hints after classification.
