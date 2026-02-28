# 🛡️ AgentGuard

> **Multi-Agent Security & Governance Platform for Enterprise AI**
> Team NamoFans | IIT Kharagpur | AI Unlocked 2026 — Track 5: Trustworthy AI

---

## 🧠 What is AgentGuard?

AgentGuard is a **Guardian Agent** that sits between AI agents and their actions, intercepting and validating every operation **before execution**. It implements a 4-layer defense-in-depth architecture to protect multi-agent systems from prompt injection, data exfiltration, and behavioral anomalies.

**Guardrails AI validates what the model *says*. AgentGuard validates what the agent *does*.**

## 📁 Repository Structure

```
AgentGuard_NamoFans/
├── src/                        # Source code
│   └── agentguard/             # Main package
├── tests/                      # Unit & integration tests
├── notebooks/                  # Jupyter notebooks & experiments
├── assets/                     # Images, architecture diagrams, presentation assets
├── docs/                       # Documentation & team briefing
│   └── TEAM_BRIEFING.md        # ⭐ Start here — full team action plan
├── Idea_submission/            # Original idea submission PDF
├── Azure-AI-Fundamentals/      # Azure learning resources
├── resources-AI-Governance/    # AI governance resources
├── AI-Unlocked-Track-*.pdf     # Track evaluation presentations
└── pyproject.toml              # Project config (managed by uv)
```

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (package manager)
- Azure subscription with credits activated

### Setup
```bash
# Clone the repo
git clone <repo-url>
cd AgentGuard_NamoFans

# Install dependencies
uv sync

# Copy environment template and add your keys
cp .env.example .env

# Run the project
uv run python -m agentguard
```

## 🔧 Tech Stack

| Component | Technology |
|---|---|
| Agent Framework | Microsoft AutoGen + Magentic-One |
| Security L1 | Azure AI Content Safety + Prompt Shields |
| Security L2 | Guardrails AI |
| Security L3 | Custom Pattern Matching |
| Security L4 | Behavioral Anomaly Engine |
| LLM Backend | Azure OpenAI (GPT-4o) |
| Deployment | Azure Container Apps |

## 👥 Team

| Member | Role |
|---|---|
| Animesh Raj | Research & Docs |
| Atul Singh | AI/ML Architecture |
| Devansh Gupta | Backend & Cloud |
| Prem Agarwal | Security & Safety |
| Mohd Faizan Khan | Backend & Cloud |

## 📄 License

This project is developed as part of the Microsoft AI Unlocked 2026 hackathon.
