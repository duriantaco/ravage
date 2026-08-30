---
title: Model Providers
---

# Model Providers

Ravage routes model calls through named profiles and tiers. `ravage attack`
infers a configured hosted route when these flags are omitted; use the flags to
override that choice. Benchmark commands continue to use explicit routes.

```text
--model-config PATH
--model-profile PROFILE
--model-tier high|mid|low
```

After `ravage init URL`, put the provider key in `.env.ravage` beside the brief.
`attack` and its doctor workflow load that file directly, so it must not be
shell-sourced. Check readiness before spending model calls:

```bash
ravage doctor --workflow attack --brief brief.yaml
```

Hosted providers receive model prompts containing the engagement brief,
selected discovered state, prior findings, and tool observations. Those
observations may include target response data. Confirm that the engagement
permits that transfer and review the provider's data-retention terms. Use a
local route when target evidence must remain on your machine.

XBEN does not load a brief-adjacent environment file. Enter its hosted key
without putting the value in shell history, export it only for the benchmark,
and unset it afterwards:

```bash
read -rsp "OpenAI API key: " OPENAI_API_KEY && printf '\n'
export OPENAI_API_KEY
# run the bounded preflight and benchmark commands
unset OPENAI_API_KEY
```

The older `ravage --print-model-routes` command is not an active public entry
point in the current CLI. Use `doctor --workflow attack` for operator
validation and inspect `examples/model_profiles.yaml` or
`packages/ravage/src/ravage/model_core/providers.py` when you need the
checked-in route definitions.

## Local Ollama

Start Ollama:

```bash
ollama serve
```

Verify the OpenAI-compatible endpoint:

```bash
curl -sS http://127.0.0.1:11434/v1/models
```

Set the model and base URL:

```bash
export RAVAGE_OLLAMA_MODEL=qwen2.5-coder:32b
export OLLAMA_BASE_URL=http://localhost:11434/v1
```

Use:

```text
--model-profile local-ollama --model-tier mid
```

## LM Studio

In LM Studio, start the local OpenAI-compatible server. The default base URL is
usually:

```text
http://localhost:1234/v1
```

Verify:

```bash
curl -sS http://127.0.0.1:1234/v1/models
```

Set:

```bash
export RAVAGE_LMSTUDIO_MODEL=local-model
export LMSTUDIO_BASE_URL=http://localhost:1234/v1
```

Use:

```text
--model-profile local-lmstudio --model-tier mid
```

## vLLM

Start vLLM with its OpenAI-compatible server. The default profile expects:

```text
http://localhost:8000/v1
```

Verify:

```bash
curl -sS http://127.0.0.1:8000/v1/models
```

Set:

```bash
export RAVAGE_VLLM_MODEL=local-model
export VLLM_BASE_URL=http://localhost:8000/v1
```

Use:

```text
--model-profile local-vllm --model-tier mid
```

## LiteLLM

LiteLLM is the simplest route for many hosted and local providers through one
OpenAI-compatible endpoint. The built-in profile expects:

```text
http://localhost:4000/v1
```

Verify:

```bash
curl -sS http://127.0.0.1:4000/v1/models
```

Set:

```bash
export RAVAGE_LITELLM_MID_MODEL=openai/gpt-5.4
export LITELLM_BASE_URL=http://localhost:4000/v1
```

The built-in `universal-litellm` profile is intentionally unpriced because a
LiteLLM model name does not prove which upstream deployment, markup, or billing
policy the proxy uses. It therefore reports `ready=false` until you copy the
route into a model config and provide explicit input, cached-input, and output
prices. Use zero only for a deployment you operate and know is nonbillable.

After pricing that route, use:

```text
--model-profile universal-litellm --model-tier mid
```

## Hosted OpenAI-Compatible Routes

For `hosted-openai`:

```dotenv
# .env.ravage
OPENAI_API_KEY=your_key_here
RAVAGE_OPENAI_MID_MODEL=gpt-5.4-2026-03-05
```

Use:

```text
--model-profile hosted-openai --model-tier mid
```

Hosted routes are paid-risk routes. `ravage attack` and `ravage xben` block them
by default until you pass `--allow-paid-models`.

The built-in direct OpenAI routes pin GPT-5.4 snapshots and apply OpenAI's
standard per-token prices for the recognized GPT-5.4 and GPT-5.4 mini snapshot
or alias names. Those prices were verified on 2026-08-15 against the
[official API pricing table](https://developers.openai.com/api/docs/pricing).
For GPT-5.4 requests above 272,000 input tokens, Ravage automatically applies
the published long-context rates.
An unknown `RAVAGE_OPENAI_*_MODEL` override remains unpriced and is not ready,
so Ravage rejects it before a paid request. Use a custom model config with
current input, cached-input, and output prices when selecting another model.

## Native Anthropic Routes

For `hosted-anthropic`:

```dotenv
# .env.ravage
ANTHROPIC_API_KEY=your_key_here
RAVAGE_ANTHROPIC_MID_MODEL=claude-sonnet-4-6
```

Use:

```text
--model-profile hosted-anthropic --model-tier mid
```

Ravage calls Anthropic's native Messages API directly with `x-api-key`,
`anthropic-version: 2023-06-01`, and `POST /v1/messages`. Other providers use
OpenAI-compatible chat completions unless routed through a custom gateway.

The built-in tiers use active pinned or canonical Anthropic IDs: Opus 4.7
(`claude-opus-4-7`), Sonnet 4.6 (`claude-sonnet-4-6`), and the pinned Haiku 4.5
snapshot (`claude-haiku-4-5-20251001`). Ravage applies the published standard
input, cache-read, and output rates of `$5/$0.50/$25`, `$3/$0.30/$15`, and
`$1/$0.10/$5` per million tokens, respectively. These IDs and prices were
verified on 2026-08-30 against Anthropic's [model-ID
reference](https://platform.claude.com/docs/en/about-claude/models/model-ids-and-versions),
[lifecycle table](https://platform.claude.com/docs/en/about-claude/model-deprecations),
and [pricing table](https://platform.claude.com/docs/en/about-claude/pricing).
An unknown `RAVAGE_ANTHROPIC_*_MODEL` override is not ready until its prices are
provided explicitly in a custom model config.

## Attack Example

Run the local Acme lab first:

```bash
ravage lab up ravage-acme-box
```

Then run the agent with a local route:

```bash
RAVAGE_OLLAMA_MODEL=qwen2.5-coder:32b \
OLLAMA_BASE_URL=http://localhost:11434/v1 \
ravage attack examples/labs/ravage-acme-box/brief.yaml \
  --model-profile local-ollama \
  --model-tier mid \
  --tool-runtime auto \
  --memory off \
  --max-turns 18
```

For hosted routes:

```bash
ravage attack examples/labs/ravage-acme-box/brief.yaml \
  --model-profile hosted-openai \
  --model-tier low \
  --allow-paid-models \
  --tool-runtime docker \
  --memory off \
  --max-turns 18
```

## XBEN Example

Run preflight first. It writes `preflight.json` and does not call the
model:

```bash
ravage xben \
  --benchmarks-root /path/to/xbow-validation-benchmarks/benchmarks \
  --output-dir runs/xben/hosted-openai-preflight \
  --ids XBEN-001-24 \
  --mode black-box \
  --comparison-profile mapta-awe-xben \
  --agent-mode ctf-free-roam \
  --model-profile hosted-openai \
  --model-tier low \
  --max-turns 4 \
  --max-model-requests-per-case 4 \
  --max-cost-usd 5 \
  --preflight
```

After inspecting preflight:

```bash
ravage xben \
  --benchmarks-root /path/to/xbow-validation-benchmarks/benchmarks \
  --output-dir runs/xben/hosted-openai-canary \
  --ids XBEN-001-24 \
  --mode black-box \
  --comparison-profile mapta-awe-xben \
  --agent-mode ctf-free-roam \
  --model-profile hosted-openai \
  --model-tier low \
  --max-turns 4 \
  --max-model-requests-per-case 4 \
  --max-cost-usd 5 \
  --allow-paid-models
```

To use Claude directly, swap the profile and key:

```bash
read -rsp "Anthropic API key: " ANTHROPIC_API_KEY && printf '\n'
export ANTHROPIC_API_KEY
ravage xben \
  --benchmarks-root /path/to/xbow-validation-benchmarks/benchmarks \
  --output-dir runs/xben/anthropic-preflight \
  --ids XBEN-001-24 \
  --mode black-box \
  --comparison-profile mapta-awe-xben \
  --agent-mode ctf-free-roam \
  --model-profile hosted-anthropic \
  --model-tier low \
  --max-turns 4 \
  --max-model-requests-per-case 4 \
  --max-cost-usd 5 \
  --preflight
unset ANTHROPIC_API_KEY
```

## Custom OpenAI-Compatible Endpoint

Create a small profile file:

```yaml
profiles:
  remote-ci:
    default_tier: mid
    routes:
      mid:
        - provider: custom_openai
          model: your-model-name
          base_url: https://your-endpoint.example/v1
          api_key_env: YOUR_API_KEY_ENV
          max_output_tokens: 1024
          output_token_limit_parameter: max_tokens
          input_cost_per_1m_tokens: 1.0
          cached_input_cost_per_1m_tokens: 1.0
          output_cost_per_1m_tokens: 2.0
```

Then use it:

```bash
read -rsp "Provider API key: " YOUR_API_KEY_ENV && printf '\n'
export YOUR_API_KEY_ENV
ravage xben \
  --benchmarks-root /path/to/xbow-validation-benchmarks/benchmarks \
  --output-dir runs/xben/remote-ci-canary \
  --ids XBEN-001-24 \
  --mode black-box \
  --model-config /path/to/model-profile.yaml \
  --model-profile remote-ci \
  --model-tier mid \
  --max-cost-usd 5 \
  --allow-paid-models
unset YOUR_API_KEY_ENV
```

Paid-risk routes are ready only when `input_cost_per_1m_tokens`,
`cached_input_cost_per_1m_tokens`, and `output_cost_per_1m_tokens` are all
present. Use current prices from your provider dashboard. If the endpoint does
not discount cached input, set its cached-input rate equal to its input rate.

## Supported Provider Kinds

Provider kinds remain accepted by the route schema so external adapters can
describe them, but only implemented transports can become ready for Ravage's
built-in chat client:

| Provider kind | Built-in direct transport | Required configuration |
| --- | --- | --- |
| `openai` | Yes, native OpenAI | Default native endpoint; use `custom_openai` for gateways |
| `anthropic` | Yes, native Messages API | Default native endpoint; use LiteLLM for gateways |
| `ollama`, `lmstudio`, `llamacpp`, `vllm` | Yes, OpenAI-compatible local | A reachable local endpoint |
| `litellm` | Yes, OpenAI-compatible gateway | Gateway URL plus explicit pricing |
| `custom_openai` | Yes, OpenAI-compatible gateway | Explicit `base_url` plus explicit pricing |
| `gemini`, `openrouter`, `azure`, `bedrock`, `vertex` | No | Use a configured LiteLLM or `custom_openai` gateway |
| `groq`, `together`, `fireworks`, `mistral`, `deepseek` | No | Use a configured LiteLLM or `custom_openai` gateway |

Unsupported direct provider kinds report `ready=false`, even if credentials
and pricing are present. The built-in client rejects them before constructing
or sending an HTTP request, so a provider key cannot fall through to OpenAI's
default endpoint.

## Troubleshooting

Connection refused means the model server is not listening at the configured
base URL. Check:

```bash
curl -sS "$OLLAMA_BASE_URL/models"
curl -sS "$LMSTUDIO_BASE_URL/models"
curl -sS "$LITELLM_BASE_URL/models"
```

Missing provider keys or invalid brief/model settings are surfaced by:

```bash
ravage doctor --workflow attack --brief brief.yaml
```

If the model returns prose instead of JSON, `ai-web` records
`invalid_model_action`, sends a correction observation, and continues until the
turn budget is exhausted.
