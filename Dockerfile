FROM python:3.12-slim

# Copy uv binary from official image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app

# Copy dependency files first (layer cache optimisation)
# README.md required by hatchling for package build
COPY pyproject.toml uv.lock README.md ./

# Copy source and test bots (needed by demo)
COPY src/ src/
COPY test_bots/ test_bots/

# Install all deps (frozen = exact lock file, no network drift)
RUN uv sync --frozen

EXPOSE 8765

# Dashboard binds 0.0.0.0 by default; Jaeger query URL overridden via env
CMD ["uv", "run", "agentguard", "dashboard", "--config", "src/agentguard-docker.yaml"]
