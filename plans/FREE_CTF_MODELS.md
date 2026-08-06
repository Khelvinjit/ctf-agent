# Free and Local Models for CTF Challenges

Research snapshot: 2026-08-06. “Free” means either an ongoing no-cost API tier,
an explicitly limited trial credit, or local inference where the operator supplies
the hardware. Rate limits, model availability, and data-use policies can change;
check the linked provider page before relying on a model for an event.

## Recommendation

Start with **Gemini 3.6 Flash** for the default agent and **Groq GPT-OSS 120B**
as the fast, independent fallback. Add **Ollama DeepSeek-R1 8B** as a completely
local/offline option. Use OpenRouter’s free router only for experimentation: it
is deliberately dynamic and has a 50-request/day free-account limit.

All hosted models send the challenge description, inventory, command outputs,
and retrieved hints to that provider. Do not use a hosted option for challenge
material that must remain private.

## Provider and model shortlist

| Model | Access | CTF fit | Key required? | Integration priority |
|---|---|---|---|---|
| Google Gemini 3.6 Flash | Gemini API free tier, subject to account/model quotas | Strong general agent; native tools; good default | Yes | 1 |
| Google Gemini 3.5 Flash-Lite | Gemini API free tier, subject to quotas | Faster/cheaper triage and simple encodings | Yes | 2 |
| Groq `openai/gpt-oss-120b` | Groq free plan | Strong reasoning/coding fallback; OpenAI-compatible API | Yes | 1 |
| Groq `openai/gpt-oss-20b` | Groq free plan | Fast lower-capacity fallback | Yes | 2 |
| Groq `qwen/qwen3.6-27b` | Groq free plan | Alternate coding/reasoning model | Yes | 2 |
| OpenRouter `openrouter/free` | OpenRouter free-model router | Useful availability fallback; model changes per request | Yes | 3 |
| OpenRouter `deepseek/deepseek-r1:free` | Free variant when currently listed | Deliberate crypto/math reasoning; availability is not guaranteed | Yes | 3 |
| Cerebras `gpt-oss-120b` | $5 sign-up trial credit | Very fast large-model evaluation; supports function calling | Yes | 4 |
| Cerebras `zai-glm-4.7` (preview) | $5 sign-up trial credit | Reasoning-oriented comparison option; preview availability may change | Yes | 4 |
| Ollama `deepseek-r1:8b` | Local | Private/offline reasoning on modest capable hardware | No | 1 |
| Ollama `deepseek-r1:32b` | Local | Better local reasoning if RAM/VRAM permits | No | 3 |
| Ollama `gpt-oss:20b` | Local | Tool-capable local alternative | No | 2 |
| Ollama `qwen3:8b` | Local | Lightweight local coding/triage option | No | 2 |

Google documents a free Developer API tier with limited model access and free
input/output tokens; check actual per-project quotas in AI Studio. [Gemini
pricing](https://ai.google.dev/gemini-api/docs/pricing) and [rate-limit
documentation](https://ai.google.dev/gemini-api/docs/rate-limits) describe the
current limits.

Groq’s free-plan table currently lists 30 RPM for the GPT-OSS and Qwen entries,
with 1,000 RPD for the listed larger models. [Groq free-plan rate
limits](https://console.groq.com/docs/rate-limits) and [supported
models](https://console.groq.com/docs/models) are the source of truth.

OpenRouter’s free router selects an available free model that supports required
features; fixed `:free` model variants can disappear or change rate limits. New
free accounts are currently limited to 50 free requests/day. See [Free Models
Router](https://openrouter.ai/docs/cookbook/get-started/free-models-router-playground),
[free variants](https://openrouter.ai/docs/guides/routing/model-variants/free),
and the [rate-limit FAQ](https://openrouter.ai/docs/faq).

Cerebras advertises a $5 trial credit rather than a permanent free tier. Its
current public model catalogue includes `gpt-oss-120b` with function-calling
capability and preview `zai-glm-4.7`; free-tier limits can change. See
[Cerebras pricing](https://www.cerebras.ai/pricing) and [public model
metadata](https://inference-docs.cerebras.ai/api-reference/models/public-models).

The Ollama library exposes DeepSeek-R1 sizes from 1.5B through 671B, and its
local OpenAI-compatible endpoint accepts a dummy key that is ignored. See the
[DeepSeek-R1 library page](https://ollama.com/library/deepseek-r1) and [Ollama
OpenAI compatibility documentation](https://docs.ollama.com/api/openai-compatibility).

## Get credentials or prepare the local runtime

### Gemini 3.6 Flash / Flash-Lite

1. Sign in to [Google AI Studio](https://aistudio.google.com/).
2. Create a Gemini API key in the API-key page, then copy it once.
3. Add it to the untracked `.env` file:

   ```dotenv
   GEMINI_API_KEY=...
   MODEL_PROVIDER=gemini
   MODEL_NAME=gemini-3.6-flash
   ```

4. Verify the current free quota in AI Studio before a long solve. For cheaper
   triage, set `MODEL_NAME=gemini-3.5-flash-lite`.

### Groq GPT-OSS / Qwen

1. Create an account at [GroqCloud](https://console.groq.com/).
2. Create a key on the [API Keys](https://console.groq.com/keys) page.
3. Save it locally:

   ```dotenv
   GROQ_API_KEY=...
   MODEL_PROVIDER=groq
   MODEL_NAME=openai/gpt-oss-120b
   ```

4. Check the account’s Limits page; rate limits apply to the organization. The
   [Groq quickstart](https://console.groq.com/docs/quickstart) documents the
   environment variable convention.

### OpenRouter free router / DeepSeek-R1 free variant

1. Create an OpenRouter account and create a regular API key in its dashboard.
2. Store the key in `.env`:

   ```dotenv
   OPENROUTER_API_KEY=...
   MODEL_PROVIDER=openrouter
   MODEL_NAME=openrouter/free
   ```

3. To test a specific free model, replace the model name with a currently
   available `:free` ID, for example `deepseek/deepseek-r1:free`.
4. Query `GET /api/v1/models` at run time and verify that the selected model
   still has zero pricing and supports tools before choosing it. Do not hard-code
   the free catalogue into the application.

### Cerebras trial

1. Register at [Cerebras Cloud](https://cloud.cerebras.ai/).
2. Create an API key and add it to `.env`:

   ```dotenv
   CEREBRAS_API_KEY=...
   MODEL_PROVIDER=cerebras
   MODEL_NAME=gpt-oss-120b
   ```

3. Treat it as a capped evaluation budget. Query `/v1/models` before a solve,
   record consumed credits, and disable the provider automatically when the
   trial is exhausted.

### Ollama local models

1. Install [Ollama](https://ollama.com/download) and start its local service.
2. Pull one model that fits the machine, for example:

   ```sh
   ollama pull deepseek-r1:8b
   ollama pull gpt-oss:20b
   ollama pull qwen3:8b
   ```

3. No secret is needed. Configure the project to reach the local endpoint:

   ```dotenv
   MODEL_PROVIDER=ollama
   MODEL_NAME=deepseek-r1:8b
   OLLAMA_BASE_URL=http://127.0.0.1:11434/v1
   ```

4. Keep Ollama on the host, not inside the challenge sandbox. The agent process
   can call it; untrusted challenge code must never gain access to its endpoint.

## Integration plan

### Phase A — provider abstraction

1. Split `ctf_agent/models/client.py` into a provider registry and adapters:
   `gemini`, `openrouter`, `groq`, `cerebras`, `huggingface`, and `ollama`.
2. Keep the existing normalized `ModelResponse` / `ToolCall` interface. Each
   adapter owns request serialization, native tool-result messages, retryable
   errors, and provider-specific thinking metadata.
3. Add `model_base_url`, `model_api_key_env`, and `model_timeout_seconds` to
   settings. Never log key values.
4. Add a `ProviderCapabilities` record: `tools`, `thinking`, `vision`,
   `context_window`, `local`, and `cost_mode` (`free`, `trial`, `paid`). Reject
   a configured model that cannot support the solver’s tool loop.

**Acceptance check:** a fake server verifies that all adapters normalize a text
turn, a tool call, and a tool result without provider-specific objects leaking
into the solver loop.

### Phase B — OpenAI-compatible adapters

1. Implement one hardened OpenAI-compatible transport for Groq, Cerebras,
   Hugging Face, and Ollama; configure only base URL, key environment variable,
   and model ID per provider.
2. Reuse the OpenRouter message adapter only where its provider-specific
   response fields are supported. Preserve any returned tool-call metadata.
3. Map `429`/temporary `5xx` failures to a retryable error with exponential
   backoff bounded by the challenge deadline.
4. Add model discovery commands for providers that expose `/v1/models`; cache
   only non-secret capability metadata with a short TTL.

**Acceptance check:** contract tests run against local mock servers and prove
that Groq/Ollama-shaped function calls continue to a second turn.

### Phase C — local Ollama support

1. Add `MODEL_PROVIDER=ollama` with default base URL
   `http://127.0.0.1:11434/v1` and a startup health check.
2. Add `--check-model` to test reachability, installed model presence, tool
   support, and available context before a challenge starts.
3. Add explicit user-facing memory guidance rather than guessing hardware:
   recommend `deepseek-r1:8b` / `qwen3:8b` first; let the operator opt into
   20B/32B models after a successful local test.

**Acceptance check:** with Ollama stopped, the CLI gives a clear setup error;
with a small pulled model, a fixture completes a two-tool solve offline.

### Phase D — selection and resilience

1. Add a `models.yaml` catalog with named profiles, provider environment
   variable, model ID, capability requirements, and a conservative request
   budget. Keep dynamic OpenRouter free models out of this static catalog.
2. Add `--model-profile` and `--fallback-profile`. Fallback occurs only on
   provider unavailability, rate limiting, or malformed tool responses—not
   after a speculative solve attempt.
3. Preserve the same sandbox, transcript, and remaining deadline across a
   fallback. Label every transcript event with provider and model.
4. Keep the current one-agent contract: this is sequential failover, not a
   multi-model swarm.

**Acceptance check:** a fixture simulates a Groq 429 and continues with a
configured local Ollama profile without repeating completed commands.

### Phase E — CTF evaluation before defaulting any model

1. Build an authorized, deterministic fixture set: Caesar/Base64, AES key
   search, RSA related-message, image metadata, archive traversal rejection,
   ELF strings, and a local HTTP web puzzle.
2. Measure solved rate, invalid-flag rate, tool-call success, time-to-first
   useful command, tokens/requests, and rate-limit failures for every profile.
3. Require placeholder-flag rejection and evidence-backed final flags in every
   evaluation.
4. Promote a profile to default only after it meets the safety and reliability
   gates; publish results by model version and test date.

## Operational guardrails

- Keep `.env` and any generated provider configuration out of Git; use distinct
  keys with a small spend/usage cap where a provider offers one.
- Prefer local Ollama for sensitive material. Free hosted tiers may use prompts
  for service improvement or otherwise have different data terms.
- Set request budgets below the provider’s daily limit; do not retry a 429 in a
  tight loop.
- Do not grant models direct Docker, host filesystem, or unrestricted network
  access. All providers use the existing constrained sandbox command tool.
- Revalidate hosted model IDs and capabilities at startup. Free catalogues are
  not stable APIs.
