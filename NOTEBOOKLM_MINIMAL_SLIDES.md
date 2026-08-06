# NotebookLM Slide-Generation Brief — CTF Agent

Use `SUBMISSION_WRITEUP.md` as the factual source. Create a **minimalistic, technical 8-slide presentation** explaining the CTF Agent solution. Do not invent a flag, benchmark, exploitation payload, or claim of successful access that is not stated in the source document.

## Audience and goal

Audience: CTF judges and technically literate evaluators.

Goal: In under 6 minutes, make clear that the project is a practical LLM agent harness for authorised CTF challenges that balances solving capability, safety, reproducibility, and cost control.

## Visual direction

- Format: 16:9 widescreen.
- Style: minimal, modern, security/engineering oriented.
- Palette: near-black or white background; one restrained accent colour (electric blue or teal); use red only for blocked/denied paths.
- Typography: one clean sans-serif family; large headline; short body text; generous whitespace.
- Use simple line icons and thin-outline diagrams. Avoid stock photography, 3D art, gradients, busy circuit-board motifs, and decorative code backgrounds.
- Put no more than 3–4 short bullets on a slide. Prefer diagrams, labelled flow arrows, and compact tables.
- Use exact terms from the source: “authorised,” “minimal capability,” “read-only /materials,” “no network by default,” and “verified flag.”

## Slides

### Slide 1 — Title

Title: **CTF Agent**

Subtitle: **A materials-first, least-privilege LLM harness for authorised CTF challenges**

Small supporting line: *Classify → build the smallest sandbox → investigate → verify → audit*

Visual: a single thin horizontal pipeline with five labelled stages. Keep the slide almost empty.

### Slide 2 — The problem

Title: **Why a generic CTF agent is not enough**

Use three concise problems:

- Full CTF images are slow, broad, and distracting.
- Untrusted files and model-generated commands need strong containment.
- A useful result must be reproducible and explainable—not just a guessed flag.

Visual: a split comparison. Left, a faded oversized “everything installed” box. Right, a clean small “evidence-selected tools” box. Add a small shield icon on the right.

### Slide 3 — Core insight

Title: **Classify before you build**

Use one sentence: *The agent sees only the description and a safe inventory first, then selects at most two relevant capabilities for the initial sandbox.*

Visual: four-step flow:

```text
Description + file inventory → Theme decision → Minimal manifest → Purpose-built Docker image
```

Add small examples below the manifest: `crypto`, `reverse`, `forensics`, `web`. Emphasise that `base` tools are always available.

### Slide 4 — Harness architecture

Title: **Architecture: a bounded agent loop**

Visual: a clear system diagram with these components and arrows:

```text
Authorised challenge materials
  → Safe inventory + LLM triage
  → Sandbox planner
  → Isolated Docker sandbox
  ↔ LLM solver loop
  → Verified FLAG + logs
```

Show an optional dashed arrow from “LLM solver loop” to “Local technique index.”

Add only these labels around the diagram: *structured classification*, *bounded tools*, *one validated expansion*, *auditable outputs*.

### Slide 5 — Security model

Title: **Security by default, not by prompt**

Visual: a container diagram with allowed and blocked paths.

Inside container labels:

- non-root `solver`
- read-only `/materials`
- temporary `/tmp`
- memory, PID, and command limits

Outside container labels:

- host attachments: **never executed during inventory**
- network: **blocked by default**

Show the one exception as a blue arrow: *explicit challenge URL → allow-listed egress proxy → declared target only*. Use red blocked arrows for host discovery, private/loopback targets, and arbitrary internet access.

### Slide 6 — Reliability and control

Title: **The agent can continue without starting over**

Three compact blocks:

- **Bounded reasoning:** iteration, command, and challenge deadlines.
- **Model resilience:** Gemini key rotation with optional Groq/OpenRouter fallback routes.
- **Durable evidence:** compact handoff + fingerprint-gated resume.

Visual: a small timeline:

```text
Model budget reached → Handoff with recent commands/evidence → Next compatible route → Continue from one new hypothesis
```

Mention that tool outputs are compacted while retaining their useful beginning and end.

### Slide 7 — Challenge handling and technology stack

Title: **Applied to the ModelHub challenge**

Left side: concise challenge handling:

- Declared target URL is recorded and preflighted.
- `POST /upload` then `POST /infer` become evidence-driven investigation steps.
- No unverified exploit or flag claim.

Right side: a compact stack grid, grouped as:

- **Core:** Python 3.11+, Bash, Docker, Ubuntu 24.04
- **LLM:** Gemini REST, Groq, OpenRouter, function calling
- **App:** httpx, Pydantic Settings, SQLite FTS, pytest
- **CTF profiles:** pycryptodome, gmpy2, radare2, gdb, pwntools, exiftool, tshark, steghide

Keep this readable; do not show package versions except Python 3.11+ and Ubuntu 24.04.

### Slide 8 — Outcome

Title: **A solver that is capable, controlled, and auditable**

Use three final takeaways:

- **Capability:** targeted LLM investigation with category-specific tools.
- **Control:** least-privilege Docker environments and strict network boundaries.
- **Confidence:** verified flags plus decisions, manifests, transcript, and write-up logs.

Bottom line in accent colour: **`FLAG: <verified value>` — only after evidence supports it.**

Visual: a very simple three-column icon layout ending in a small audit-log/checkmark icon.

## Output constraints

- Minimal text and no dense paragraphs.
- One architecture diagram and one security-boundary diagram.
- No citations slide and no appendix.
- The result should look presentation-ready without needing manual cleanup.
