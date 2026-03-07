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

## LiteLLM Usage

Always use LiteLLM for all LLM calls — never call provider SDKs (OpenAI, Anthropic, etc.) directly.

- **Import:** `from litellm import completion` (or `acompletion` for async)
- **Model strings:** use provider-prefixed format — `"openai/gpt-4o"`, `"anthropic/claude-sonnet-4-6"`, `"azure/my-deployment"`, etc.
- **LLM provider:** TrueFoundry — env vars `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`
- **Azure Content Safety (L1):** `CONTENT_SAFETY_ENDPOINT` + `CONTENT_SAFETY_KEY` → `https://agentguard.cognitiveservices.azure.com/`
- **Azure Language / PII (L2):** `AZURE_LANGUAGE_ENDPOINT` + `AZURE_LANGUAGE_KEY` → `https://lang-anal-ag.cognitiveservices.azure.com/`
- **Config via env vars:** all keys live in `.env` (gitignored); never hardcode credentials
- **Structured output:** use `response_format=` with a Pydantic model or `{"type": "json_object"}` — do not parse raw strings
- **No direct SDK instantiation:** do not create `anthropic.Anthropic()` or `openai.OpenAI()` clients; route everything through LiteLLM

```python
# correct — TrueFoundry via LiteLLM
from litellm import completion
import os

response = completion(
    model="openai/" + os.environ["OPENAI_MODEL"],
    api_key=os.environ["OPENAI_API_KEY"],
    api_base=os.environ["OPENAI_BASE_URL"],
    messages=[{"role": "user", "content": prompt}],
)

# wrong — do not do this
import anthropic
client = anthropic.Anthropic()
client.messages.create(...)
```

## Task Tracking

Before implementing any plan:
1. Create a task list breaking the plan into discrete, trackable steps — do this before writing any code
2. Mark tasks **in-progress** when starting, **completed** when done
3. Use the task list to track progress through each step
