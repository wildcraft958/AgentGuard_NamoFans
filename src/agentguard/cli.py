"""
AgentGuard CLI — `agentguard test` command.

Two execution paths:

Easy path (auto-generated Promptfoo config from testing: block):
    agentguard test --config src/agentguard.yaml \\
                    --module test_bots/financial_agent.py [--function run]

Advanced path (escape hatch — bring your own Promptfoo config):
    agentguard test --promptfoo-config my_custom_redteam.yaml \\
                    [--module test_bots/my_agent.py]

Non-interactive: all npx invocations use `npx --yes promptfoo@latest ...`
so promptfoo is installed automatically without blocking.
"""

import argparse
import logging
import os
import subprocess
import sys

import yaml

logger = logging.getLogger("agentguard.cli")

_BRIDGE_MODULE = os.path.join(os.path.dirname(__file__), "promptfoo_bridge.py")


def generate_promptfoo_config(
    config_path: str,
    agent_module: str | None,
    function_name: str | None,
    output_path: str,
) -> dict:
    """
    Read the agentguard.yaml testing: block and generate a promptfooconfig.yaml.

    Pure function — fully testable without subprocess.

    Args:
        config_path: Path to agentguard.yaml.
        agent_module: Path to the agent Python file (AGENTGUARD_AGENT_MODULE).
        function_name: Function name inside the module (AGENTGUARD_FUNCTION).
        output_path: Where to write the generated promptfooconfig.yaml.

    Returns:
        The generated config dict.
    """
    try:
        with open(config_path, "r") as f:
            raw = yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.error("Config file not found: %s", config_path)
        return {}

    testing = raw.get("testing", {})
    if not testing:
        logger.warning("No 'testing:' block found in %s — nothing to generate.", config_path)
        return {}

    # Build provider config env vars
    provider_config: dict = {
        "AGENTGUARD_CONFIG": config_path,
    }
    if agent_module:
        provider_config["AGENTGUARD_AGENT_MODULE"] = agent_module
    if function_name:
        provider_config["AGENTGUARD_FUNCTION"] = function_name

    # Resolve bridge path relative to output directory so Promptfoo can find it
    bridge_path = os.path.abspath(_BRIDGE_MODULE)
    provider = {
        "id": f"python:{bridge_path}",
        "config": provider_config,
    }

    # Build plugins list
    plugins = testing.get("plugins", [])

    # Build strategies list
    strategies = testing.get("strategies", [])

    # Build custom tests
    custom_tests = []
    for ct in testing.get("custom_tests", []):
        test_entry = {
            "vars": {"prompt": ct.get("query", "")},
        }
        if "assert" in ct:
            test_entry["assert"] = ct["assert"]
        custom_tests.append(test_entry)

    pf_config = {
        "providers": [provider],
        "redteam": {
            "purpose": testing.get("purpose", ""),
            "plugins": plugins,
            "strategies": strategies,
            "numTests": testing.get("num_tests", 25),
        },
        "tests": custom_tests,
    }

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w") as f:
        yaml.dump(pf_config, f, default_flow_style=False, allow_unicode=True)

    logger.info("Generated Promptfoo config at: %s", output_path)
    return pf_config


def run_tests(
    config_path: str,
    agent_module: str | None,
    function_name: str | None,
    promptfoo_config: str | None = None,
    output_dir: str = ".",
) -> None:
    """
    Generate Promptfoo config (if needed) and invoke `npx --yes promptfoo@latest redteam run`.

    Args:
        config_path: Path to agentguard.yaml.
        agent_module: Path to the agent Python file.
        function_name: Function name inside the module.
        promptfoo_config: Escape hatch — if provided, skip generation and use this config.
        output_dir: Where to write the auto-generated promptfooconfig.yaml.
    """
    if promptfoo_config:
        # Advanced path: user provided their own Promptfoo config
        pf_config_path = promptfoo_config
        logger.info("Using user-provided Promptfoo config: %s", pf_config_path)
    else:
        # Easy path: auto-generate from testing: block
        pf_config_path = os.path.join(output_dir, "promptfooconfig.yaml")
        result = generate_promptfoo_config(config_path, agent_module, function_name, pf_config_path)
        if not result:
            print(
                "[agentguard] No 'testing:' block configured. "
                "Add a testing: section to your agentguard.yaml to use agentguard test.",
                file=sys.stderr,
            )
            sys.exit(1)

    cmd = [
        "npx",
        "--yes",
        "promptfoo@latest",
        "redteam",
        "run",
        "--config",
        pf_config_path,
    ]

    print(f"[agentguard] Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=False)


def run_dashboard(
    host: str = "0.0.0.0",
    port: int = 8765,
    jaeger_url: str | None = None,
) -> None:
    """
    Start the AgentGuard OTel dashboard server.

    Args:
        host:       Host to bind to.
        port:       Port to listen on.
        jaeger_url: Override Jaeger query URL (sets JAEGER_QUERY_URL env var).
    """
    import uvicorn

    if jaeger_url:
        os.environ["JAEGER_QUERY_URL"] = jaeger_url

    print(f"[agentguard] Starting dashboard at http://{host}:{port}")
    if jaeger_url:
        print(f"[agentguard] Jaeger query URL: {jaeger_url}")

    uvicorn.run(
        "agentguard.dashboard.server:app",
        host=host,
        port=port,
        log_level="info",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argparse parser. Separated for testability."""
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="AgentGuard CLI — Security testing for AI agents",
    )
    subparsers = parser.add_subparsers(dest="command")

    test_parser = subparsers.add_parser(
        "test",
        help="Red-team test an agent using Promptfoo",
    )
    test_parser.add_argument(
        "--config",
        default="agentguard.yaml",
        help="Path to agentguard.yaml (default: agentguard.yaml)",
    )
    test_parser.add_argument(
        "--module",
        default=None,
        dest="module",
        help="Path to the agent Python module file",
    )
    test_parser.add_argument(
        "--function",
        default=None,
        dest="function",
        help="Name of the agent function to call (for unguarded agents without @guard_agent)",
    )
    test_parser.add_argument(
        "--promptfoo-config",
        default=None,
        dest="promptfoo_config",
        help="Escape hatch: path to a user-authored promptfooconfig.yaml (skips auto-generation)",
    )

    dash_parser = subparsers.add_parser(
        "dashboard",
        help="Start the OTel live dashboard",
    )
    dash_parser.add_argument(
        "--config",
        default="agentguard.yaml",
        help="Path to agentguard.yaml (default: agentguard.yaml)",
    )
    dash_parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port to listen on (default: 8765)",
    )
    dash_parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    dash_parser.add_argument(
        "--jaeger-url",
        default=None,
        dest="jaeger_url",
        help="Jaeger query URL (default: http://localhost:16686)",
    )

    return parser


def main():
    """Entry point for `agentguard` CLI command."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "test":
        run_tests(
            config_path=args.config,
            agent_module=args.module,
            function_name=args.function,
            promptfoo_config=args.promptfoo_config,
        )
    elif args.command == "dashboard":
        run_dashboard(
            host=args.host,
            port=args.port,
            jaeger_url=args.jaeger_url,
        )
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
