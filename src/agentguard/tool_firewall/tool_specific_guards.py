"""
AgentGuard – Tool-Specific Guards (Component 3).

Pure-Python rule-based guards for HTTP, SQL, and filesystem tool calls.
No external API calls — all checks run locally with zero latency.

Guards:
  http_post  — domain allowlist/denylist, HTTPS enforcement, private IP blocking,
               payload size limit, rate limiting
  http_get   — domain allowlist, metadata service blocking
  sql_query  — statement allowlist/denylist, row limit
  file_system — path allowlist, extension denylist, path traversal detection
"""

import ipaddress
import logging
import os
import re
import time
from urllib.parse import urlparse

from agentguard.models import ValidationResult

logger = logging.getLogger("agentguard.tool_specific_guards")

LAYER = "tool_specific_guards"

# Well-known cloud metadata service addresses
METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
}

# Private IP ranges (RFC 1918 + link-local + loopback)
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_private_ip(host: str) -> bool:
    """Check if a hostname resolves to a private IP range."""
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def _extract_domain(url_or_domain: str) -> str:
    """Extract domain from a URL or return as-is if already a domain."""
    if "://" in url_or_domain:
        parsed = urlparse(url_or_domain)
        return parsed.hostname or ""
    return url_or_domain.split("/")[0].split(":")[0]


def _domain_matches(domain: str, pattern: str) -> bool:
    """Check if domain matches a pattern (exact or subdomain)."""
    domain = domain.lower()
    pattern = pattern.lower()
    return domain == pattern or domain.endswith("." + pattern)


class ToolSpecificGuards:
    """Rule-based guards for specific tool types.

    Reads per-tool configuration from the AgentGuard config and applies
    the appropriate guard when `check()` is called.
    """

    def __init__(self, config):
        """
        Args:
            config: AgentGuardConfig instance.
        """
        self.config = config
        self._rate_counters: dict[str, list[float]] = {}

    def check(self, fn_name: str, fn_args: dict) -> ValidationResult:
        """
        Run the appropriate guard for a tool call.

        Args:
            fn_name: The tool function name.
            fn_args: The tool function arguments dict.

        Returns:
            ValidationResult — is_safe=True if allowed, False if blocked.
        """
        tool_config = self.config.get_tool_config(fn_name)

        if not tool_config or not tool_config.get("enabled", False):
            logger.debug("No guard configured for tool '%s', allowing", fn_name)
            return ValidationResult(is_safe=True, layer=LAYER)

        if tool_config.get("block_all", False):
            reason = f"Tool '{fn_name}' is blocked by policy"
            logger.warning("Tool guard BLOCKED (%s): %s", fn_name, reason)
            return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        guard_method = {
            "http_post": self._guard_http_post,
            "http_get": self._guard_http_get,
            "sql_query": self._guard_sql_query,
            "file_system": self._guard_file_system,
        }.get(fn_name)

        if guard_method is None:
            if fn_name.startswith("fs_"):
                guard_method = self._guard_file_system
            elif fn_name.startswith("db_"):
                guard_method = self._guard_sql_query
            elif fn_name.startswith("http_") or fn_name == "https_request":
                guard_method = self._guard_http_get

        if guard_method is None:
            logger.debug("No specific guard for tool '%s', allowing", fn_name)
            return ValidationResult(is_safe=True, layer=LAYER)

        return guard_method(fn_args, tool_config)

    # ------------------------------------------------------------------
    # HTTP POST guard
    # ------------------------------------------------------------------

    def _guard_http_post(self, args: dict, cfg: dict) -> ValidationResult:
        url = args.get("url", "")
        domain = _extract_domain(url)

        # HTTPS enforcement
        if cfg.get("require_https", False):
            if url and not url.startswith("https://"):
                reason = f"HTTPS required but got: {url}"
                logger.warning("Tool guard BLOCKED (http_post): %s", reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Private IP blocking
        if cfg.get("block_private_ips", False) and _is_private_ip(domain):
            reason = f"Private IP blocked: {domain}"
            logger.warning("Tool guard BLOCKED (http_post): %s", reason)
            return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Domain allowlist/denylist
        result = self._check_domain(domain, cfg, "http_post")
        if result is not None:
            return result

        # Payload size limit
        max_kb = cfg.get("max_payload_kb")
        if max_kb is not None:
            payload = args.get("body", args.get("data", args.get("payload", "")))
            payload_size = len(str(payload).encode("utf-8")) / 1024
            if payload_size > max_kb:
                reason = f"Payload too large: {payload_size:.1f}KB > {max_kb}KB limit"
                logger.warning("Tool guard BLOCKED (http_post): %s", reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Rate limiting
        rate_limit = cfg.get("rate_limit_per_minute")
        if rate_limit is not None:
            result = self._check_rate_limit(domain, rate_limit, "http_post")
            if result is not None:
                return result

        return ValidationResult(is_safe=True, layer=LAYER)

    # ------------------------------------------------------------------
    # HTTP GET guard
    # ------------------------------------------------------------------

    def _guard_http_get(self, args: dict, cfg: dict) -> ValidationResult:
        url = args.get("url", "")
        domain = _extract_domain(url)

        # Metadata service blocking
        if cfg.get("block_metadata_services", False):
            if domain in METADATA_HOSTS:
                reason = f"Cloud metadata service blocked: {domain}"
                logger.warning("Tool guard BLOCKED (http_get): %s", reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Domain allowlist/denylist
        result = self._check_domain(domain, cfg, "http_get")
        if result is not None:
            return result

        return ValidationResult(is_safe=True, layer=LAYER)

    # ------------------------------------------------------------------
    # SQL query guard
    # ------------------------------------------------------------------

    def _guard_sql_query(self, args: dict, cfg: dict) -> ValidationResult:
        query = args.get("query", args.get("sql", "")).strip()

        if not query:
            return ValidationResult(is_safe=True, layer=LAYER)

        # Extract the first SQL keyword
        first_word = re.split(r"\s+", query, maxsplit=1)[0].upper()

        # Denied statements
        denied = [s.upper() for s in cfg.get("denied_statements", [])]
        if first_word in denied:
            reason = f"SQL statement denied: {first_word}"
            logger.warning("Tool guard BLOCKED (sql_query): %s", reason)
            return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Allowed statements
        allowed = [s.upper() for s in cfg.get("allowed_statements", [])]
        if allowed and first_word not in allowed:
            reason = f"SQL statement not in allowlist: {first_word} (allowed: {', '.join(allowed)})"
            logger.warning("Tool guard BLOCKED (sql_query): %s", reason)
            return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Check for dangerous patterns within the query (e.g., DROP inside subquery)
        dangerous_patterns = denied or ["DROP", "DELETE", "TRUNCATE", "ALTER"]
        query_upper = query.upper()
        for pattern in dangerous_patterns:
            # Match the keyword as a whole word (not part of a column name)
            if re.search(rf"\b{pattern}\b", query_upper):
                reason = f"Dangerous SQL keyword found in query: {pattern}"
                logger.warning("Tool guard BLOCKED (sql_query): %s", reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        return ValidationResult(is_safe=True, layer=LAYER)

    # ------------------------------------------------------------------
    # File system guard
    # ------------------------------------------------------------------

    def _guard_file_system(self, args: dict, cfg: dict) -> ValidationResult:
        file_path = args.get("file_path", args.get("path", ""))

        if not file_path:
            return ValidationResult(is_safe=True, layer=LAYER)

        # Normalize path
        normalized = os.path.normpath(file_path)

        # Path traversal detection
        if ".." in file_path:
            reason = f"Path traversal detected: {file_path}"
            logger.warning("Tool guard BLOCKED (file_system): %s", reason)
            return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Extension denylist
        deny_extensions = cfg.get("deny_extensions", [])
        for ext in deny_extensions:
            if normalized.endswith(ext):
                reason = f"File extension denied: {ext} (path: {file_path})"
                logger.warning("Tool guard BLOCKED (file_system): %s", reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Path allowlist
        allowed_paths = cfg.get("allowed_paths", [])
        if allowed_paths:
            allowed = any(normalized.startswith(os.path.normpath(p)) for p in allowed_paths)
            if not allowed:
                reason = f"Path not in allowlist: {file_path} (allowed: {', '.join(allowed_paths)})"
                logger.warning("Tool guard BLOCKED (file_system): %s", reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        return ValidationResult(is_safe=True, layer=LAYER)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _check_domain(self, domain: str, cfg: dict, tool_name: str) -> ValidationResult | None:
        """Check domain against allowlist/denylist. Returns None if allowed."""
        mode = cfg.get("mode", "unrestricted")

        if mode == "allowlist":
            allowed_domains = cfg.get("allowed_domains", [])
            if allowed_domains and not any(_domain_matches(domain, d) for d in allowed_domains):
                reason = f"Domain not in allowlist: {domain}"
                logger.warning("Tool guard BLOCKED (%s): %s", tool_name, reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        elif mode == "denylist":
            denied_domains = cfg.get("denied_domains", [])
            if any(_domain_matches(domain, d) for d in denied_domains):
                reason = f"Domain in denylist: {domain}"
                logger.warning("Tool guard BLOCKED (%s): %s", tool_name, reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        return None

    def _check_rate_limit(self, key: str, limit: int, tool_name: str) -> ValidationResult | None:
        """Sliding-window rate limit. Returns None if within limit."""
        now = time.time()
        window_start = now - 60.0

        if key not in self._rate_counters:
            self._rate_counters[key] = []

        # Prune old timestamps
        self._rate_counters[key] = [t for t in self._rate_counters[key] if t > window_start]

        if len(self._rate_counters[key]) >= limit:
            reason = f"Rate limit exceeded: {len(self._rate_counters[key])}/{limit} per minute for {key}"
            logger.warning("Tool guard BLOCKED (%s): %s", tool_name, reason)
            return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        self._rate_counters[key].append(now)
        return None
