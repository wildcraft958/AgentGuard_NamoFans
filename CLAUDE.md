# AgentGuard — Claude Code Session Guide

## Dev Commands

```bash
uv sync                  # install dependencies
uv run pytest            # run all tests
uv run ruff check .      # lint
uv run ruff format .     # format (line-length=100)
```

## Commit Discipline

Use **conventional commits** (`type(scope): description`):

- `feat:` — new feature or capability
- `fix:` — bug fix
- `refactor:` — restructuring without behavior change
- `test:` — adding or updating tests
- `docs:` — documentation only
- `chore:` — build, deps, config

Commit when a meaningful unit of work is complete and tests pass. Keep commits atomic — no batching unrelated changes, no committing broken code.

**Auto-commit is authorized** — after completing any meaningful unit of work (feature, fix, docs update, etc.), commit and push immediately without waiting for explicit user instruction. Always lint and verify tests pass before committing.

**No co-author tags** — never include `Co-Authored-By: Claude` or any AI attribution in commit messages.

## Claude Workflow Rules

- **No explore agents** — search files directly with Glob/Grep; do not spawn Agent(subagent_type=Explore)
- **No plan agents** — plan inline in text; do not spawn Agent(subagent_type=Plan)
- **Read files directly** — use the Read tool; avoid shell `cat`/`head`/`grep` when a dedicated tool exists
- **Lint before committing** — run `uv run ruff check .` and fix issues before staging
- **Tests after changes** — run `uv run pytest` after any functional change to confirm nothing regressed
- **Minimal changes** — only touch what the task requires; do not refactor surrounding code unless explicitly asked

## TDD Workflow

**Always write or update tests before implementation.**

### Unit Tests (`tests/`)
- All unit tests live in `tests/` mirroring the source structure (e.g. `tests/l1_input/test_prompt_shields.py`)
- Test happy paths, unhappy paths, and edge cases
- Test individual functions and classes in isolation
- Mock all external dependencies (Azure APIs, HTTP calls, filesystem, etc.)
- Write the test first, watch it fail, then implement until it passes
- Run tests frequently during development — after every meaningful change

### Integration Tests (`tests/integration/`)
- Place integration tests in `tests/integration/`
- Integration tests may call real external services — require env vars (e.g. `AZURE_CONTENT_SAFETY_KEY`) to be set; skip gracefully if missing
- Test the full request path through multiple layers together (e.g. L1 + L2 combined)
- Do not mock external dependencies in integration tests — that defeats the purpose

### Running Tests

```bash
uv run pytest tests/                         # all unit tests
uv run pytest tests/integration/             # integration tests only
uv run pytest tests/ -k "test_name"          # run a specific test
uv run pytest tests/ -x                      # stop on first failure
```

## Writeup Log (`writeup.md`)

After every architectural design choice or implementation, update `writeup.md` in the project root. Each entry must cover:

- **What was added or changed** — describe the feature, module, or decision
- **Why this approach was chosen** — reasoning behind the design
- **What problem it solves** — the concrete issue or gap it addresses
- **Tradeoffs considered** — alternatives evaluated and why they were rejected or deferred
- **Examples showing it working** — code snippets, sample input/output, or test cases demonstrating the change

Append new entries; do not overwrite previous ones. Use a heading with the date and a short title, e.g.:

```markdown
## 2026-03-07 — L1 Azure Prompt Shields integration

**What changed:** ...
**Why this approach:** ...
**Problem solved:** ...
**Tradeoffs:** ...
**Example:** ...
```

## Promptfoo & DeepTeam — External Requirements

### Promptfoo (CLI red-team testing)

`agentguard test` invokes `npx promptfoo@latest` via subprocess. **Node.js and npm must be installed** on the machine.

```bash
# Install Node.js (Ubuntu/Debian)
sudo apt install nodejs npm

# Verify
node --version   # >= 18 recommended
npx --version
```

`npx --yes` auto-installs `promptfoo@latest` on first run (one-time, ~30s). Subsequent runs use the cached version.

**Usage:**
```bash
agentguard test --config src/agentguard.yaml --module test_bots/financial_agent.py
```

### DeepTeam (OWASP scanner)

`scan_agent()` calls the **OpenAI API directly** via DeepTeam — it does NOT use TrueFoundry.

- Requires `OPENAI_API_KEY=sk-...` in `.env`
- This is separate from `OPENAI_BASE_URL` (TrueFoundry) used for agent LLM calls
- Cost scales with `attacks_per_vulnerability_type` (default: 1 = ~20 API calls total for "both")
- Uses `deepteam.red_teamer.RedTeamer` (not `deepteam.RedTeamer` — wrong import path)

```python
from agentguard.owasp_scanner import scan_agent

def my_agent(prompt: str) -> str:
    return client.chat.completions.create(...).choices[0].message.content

results = scan_agent(my_agent, target="both", target_purpose="A DevOps assistant.")
print(f"Pass rate: {results.overall_pass_rate:.0%}")
```

## LLM Usage

Use the **OpenAI SDK** for all LLM calls routed through TrueFoundry. Do not use LiteLLM — it strips Gemini `thought_signature` fields from tool call responses, breaking multi-turn ReAct loops with thinking models.

- **Import:** `from openai import OpenAI`
- **Provider:** TrueFoundry gateway (OpenAI-compatible) — env vars `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`
- **Azure Content Safety (L1):** `CONTENT_SAFETY_ENDPOINT` + `CONTENT_SAFETY_KEY` → `https://agentguard.cognitiveservices.azure.com/`
- **Azure Language / PII (L2):** `AZURE_LANGUAGE_ENDPOINT` + `AZURE_LANGUAGE_KEY` → `https://lang-anal-ag.cognitiveservices.azure.com/`
- **Config via env vars:** all keys live in `.env` (gitignored); never hardcode credentials
- **Append assistant messages as-is** — do not call `.model_dump()` before appending to the message list; the OpenAI SDK uses `extra='allow'` and preserves extra fields like `thought_signature` needed for subsequent turns

```python
# correct — TrueFoundry via OpenAI SDK
from openai import OpenAI
import os

client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url=os.environ["OPENAI_BASE_URL"],
)
MODEL = os.environ["OPENAI_MODEL"]

response = client.chat.completions.create(
    model=MODEL,
    messages=messages,
    tools=tools,
)
msg = response.choices[0].message
messages.append(msg)  # append as-is — preserves thought_signature

# wrong — LiteLLM strips thought_signature, breaking Gemini multi-turn tool calls
from litellm import completion
completion(model="openai/" + MODEL, ...)
```

## Task Tracking

Before implementing any plan:
1. Create a task list breaking the plan into discrete, trackable steps — do this before writing any code
2. Mark tasks **in-progress** when starting, **completed** when done
3. Use the task list to track progress through each step
