"""
AgentGuard – Argument-Aware Guardrails (Component 3).

Pure-Python rule-based guardrails for HTTP, SQL, and filesystem protection.
No external API calls — all checks run locally with zero latency.

The 4 guardrails scan every tool call's arguments generically:
  file_system  — path allowlist, extension denylist, path traversal detection
  sql_query    — statement allowlist/denylist (uses sqlparse AST for detection)
  http_post    — domain allowlist, HTTPS enforcement, private IP blocking, payload/rate limits
  http_get     — domain allowlist, metadata service blocking

Guardrails are NOT tools. Tools are agent capabilities (fs_read_file, db_select,
custom_fetch, etc.). Guardrails protect tools by inspecting their arguments.
"""

import ipaddress
import logging
import os
import re
import time
from urllib.parse import urlparse

import sqlparse
from sqlparse.tokens import Keyword

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

# SQL structural keywords — required beyond the initial DML/DDL keyword
# to distinguish real SQL from English sentences starting with "SELECT", "UPDATE", etc.
_SQL_STRUCTURE_KEYWORDS = {
    "FROM", "TABLE", "INTO", "SET", "WHERE", "VALUES", "JOIN", "ON",
    "USING", "INDEX", "DATABASE", "SCHEMA", "VIEW", "TRIGGER", "COLUMN",
}

# Regex for filesystem path detection — rejects dates, fractions, plain text
_PATH_PATTERN = re.compile(
    r"^(?:"
    r"(?:/[^\s:*?\"<>|]+)"       # Unix absolute: /etc/passwd, /tmp/foo
    r"|(?:~/[^\s:*?\"<>|]*)"     # Home-relative: ~/Documents/file
    r"|(?:\./[^\s:*?\"<>|]*)"    # Current-dir relative: ./config.json
    r"|(?:[A-Za-z]:[/\\])"       # Windows: C:\, D:/
    r")"
)


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
    """Argument-aware guardrails that scan every tool call's arguments.

    Instead of dispatching by tool name, scans all string arguments for
    file paths, URLs, and SQL strings, then applies the matching guardrail.
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
        Run argument-aware guardrails on a tool call.

        1. Check if tool is explicitly disabled (tools: section)
        2. Check default_policy for unknown tools
        3. Scan all string args for paths, URLs, SQL → run matching guardrails

        Args:
            fn_name: The tool function name (e.g. fs_read_file, db_select).
            fn_args: The tool function arguments dict.

        Returns:
            ValidationResult — is_safe=True if allowed, False if blocked.
        """
        # Step 0: Check if tool is explicitly disabled in tools: section
        tool_config = self.config.get_tool_config(fn_name)
        if tool_config and not tool_config.get("enabled", True):
            reason = tool_config.get("reason", f"Tool '{fn_name}' is disabled")
            logger.warning("Guardrail BLOCKED (%s): %s", fn_name, reason)
            return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Step 0b: default_policy for tools not in config
        if not tool_config:
            if self.config.tool_firewall_default_policy == "deny":
                reason = f"Tool '{fn_name}' not in allowed tools (default_policy: deny)"
                logger.warning("Guardrail BLOCKED (%s): %s", fn_name, reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        if tool_config and tool_config.get("block_all", False):
            reason = f"Tool '{fn_name}' is blocked by policy"
            logger.warning("Guardrail BLOCKED (%s): %s", fn_name, reason)
            return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Step 1: Scan ALL string args, run applicable guardrails
        for arg_name, arg_value in fn_args.items():
            text = str(arg_value) if arg_value is not None else ""
            if not text.strip():
                continue

            # File path detection → file_system guardrail
            if self._looks_like_path(text):
                fs_cfg = self.config.tool_firewall_file_system_config
                if fs_cfg.get("enabled", False):
                    result = self._guard_file_system({"file_path": text}, fs_cfg)
                    if not result.is_safe:
                        return result

            # URL detection → http_post or http_get guardrail
            if self._looks_like_url(text):
                if self._is_post_context(fn_name):
                    cfg = self.config.tool_firewall_http_post_config
                    guard = self._guard_http_post
                else:
                    cfg = self.config.tool_firewall_http_get_config
                    guard = self._guard_http_get
                if cfg.get("enabled", False):
                    result = guard({"url": text, **fn_args}, cfg)
                    if not result.is_safe:
                        return result

            # SQL detection → sql_query guardrail
            if self._looks_like_sql(text):
                sql_cfg = self.config.tool_firewall_sql_query_config
                if sql_cfg.get("enabled", False):
                    result = self._guard_sql_query({"query": text}, sql_cfg)
                    if not result.is_safe:
                        return result

        return ValidationResult(is_safe=True, layer=LAYER)

    # ------------------------------------------------------------------
    # Hardened detection methods
    # ------------------------------------------------------------------

    def _looks_like_path(self, text: str) -> bool:
        """Detect filesystem paths using regex. Rejects dates, fractions."""
        t = text.strip()
        if ".." in t:
            return True  # Path traversal is always suspicious
        return bool(_PATH_PATTERN.match(t))

    def _looks_like_url(self, text: str) -> bool:
        """Detect URLs using urllib.parse. Requires valid scheme + hostname."""
        t = text.strip()
        try:
            parsed = urlparse(t)
            return parsed.scheme in ("http", "https", "ftp") and bool(parsed.netloc)
        except Exception:
            return False

    def _looks_like_sql(self, text: str) -> bool:
        """Detect SQL using sqlparse AST. Catches evasion, rejects English.

        Requires both a DML/DDL keyword AND a SQL structural keyword
        (FROM, TABLE, INTO, SET, WHERE, etc.) to distinguish real SQL
        from English sentences like 'UPDATE: meeting canceled'.
        """
        text = text.strip()
        if not text:
            return False
        try:
            parsed = sqlparse.parse(text)
            if not parsed:
                return False
            stmt = parsed[0]
            stmt_type = stmt.get_type()
            if stmt_type is None or stmt_type == "UNKNOWN":
                return False
            # Require at least one SQL structural keyword
            for token in stmt.flatten():
                if token.is_whitespace:
                    continue
                if token.ttype is Keyword and token.normalized.upper() in _SQL_STRUCTURE_KEYWORDS:
                    return True
            return False
        except Exception:
            return False

    def _is_post_context(self, fn_name: str) -> bool:
        """Detect POST-like context from tool name only."""
        name_lower = fn_name.lower()
        return "post" in name_lower or "send" in name_lower or "upload" in name_lower

    # ------------------------------------------------------------------
    # HTTP POST guardrail
    # ------------------------------------------------------------------

    def _guard_http_post(self, args: dict, cfg: dict) -> ValidationResult:
        url = args.get("url", "")
        domain = _extract_domain(url)

        # HTTPS enforcement
        if cfg.get("require_https", False):
            if url and not url.startswith("https://"):
                reason = f"HTTPS required but got: {url}"
                logger.warning("Guardrail BLOCKED (http_post): %s", reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Private IP blocking
        if cfg.get("block_private_ips", False) and _is_private_ip(domain):
            reason = f"Private IP blocked: {domain}"
            logger.warning("Guardrail BLOCKED (http_post): %s", reason)
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
                logger.warning("Guardrail BLOCKED (http_post): %s", reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Rate limiting
        rate_limit = cfg.get("rate_limit_per_minute")
        if rate_limit is not None:
            result = self._check_rate_limit(domain, rate_limit, "http_post")
            if result is not None:
                return result

        return ValidationResult(is_safe=True, layer=LAYER)

    # ------------------------------------------------------------------
    # HTTP GET guardrail
    # ------------------------------------------------------------------

    def _guard_http_get(self, args: dict, cfg: dict) -> ValidationResult:
        url = args.get("url", "")
        domain = _extract_domain(url)

        # Metadata service blocking
        if cfg.get("block_metadata_services", False):
            if domain in METADATA_HOSTS:
                reason = f"Cloud metadata service blocked: {domain}"
                logger.warning("Guardrail BLOCKED (http_get): %s", reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Domain allowlist/denylist
        result = self._check_domain(domain, cfg, "http_get")
        if result is not None:
            return result

        return ValidationResult(is_safe=True, layer=LAYER)

    # ------------------------------------------------------------------
    # SQL query guardrail
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
            logger.warning("Guardrail BLOCKED (sql_query): %s", reason)
            return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Allowed statements
        allowed = [s.upper() for s in cfg.get("allowed_statements", [])]
        if allowed and first_word not in allowed:
            reason = f"SQL statement not in allowlist: {first_word} (allowed: {', '.join(allowed)})"
            logger.warning("Guardrail BLOCKED (sql_query): %s", reason)
            return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Check for dangerous patterns within the query (e.g., DROP inside subquery)
        dangerous_patterns = denied or ["DROP", "DELETE", "TRUNCATE", "ALTER"]
        query_upper = query.upper()
        for pattern in dangerous_patterns:
            # Match the keyword as a whole word (not part of a column name)
            if re.search(rf"\b{pattern}\b", query_upper):
                reason = f"Dangerous SQL keyword found in query: {pattern}"
                logger.warning("Guardrail BLOCKED (sql_query): %s", reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        return ValidationResult(is_safe=True, layer=LAYER)

    # ------------------------------------------------------------------
    # File system guardrail
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
            logger.warning("Guardrail BLOCKED (file_system): %s", reason)
            return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Extension denylist
        deny_extensions = cfg.get("deny_extensions", [])
        for ext in deny_extensions:
            if normalized.endswith(ext):
                reason = f"File extension denied: {ext} (path: {file_path})"
                logger.warning("Guardrail BLOCKED (file_system): %s", reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        # Path allowlist
        allowed_paths = cfg.get("allowed_paths", [])
        if allowed_paths:
            allowed = any(normalized.startswith(os.path.normpath(p)) for p in allowed_paths)
            if not allowed:
                reason = f"Path not in allowlist: {file_path} (allowed: {', '.join(allowed_paths)})"
                logger.warning("Guardrail BLOCKED (file_system): %s", reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        return ValidationResult(is_safe=True, layer=LAYER)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _check_domain(self, domain: str, cfg: dict, guardrail_name: str) -> ValidationResult | None:
        """Check domain against allowlist/denylist. Returns None if allowed."""
        mode = cfg.get("mode", "unrestricted")

        if mode == "allowlist":
            allowed_domains = cfg.get("allowed_domains", [])
            if allowed_domains and not any(_domain_matches(domain, d) for d in allowed_domains):
                reason = f"Domain not in allowlist: {domain}"
                logger.warning("Guardrail BLOCKED (%s): %s", guardrail_name, reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        elif mode == "denylist":
            denied_domains = cfg.get("denied_domains", [])
            if any(_domain_matches(domain, d) for d in denied_domains):
                reason = f"Domain in denylist: {domain}"
                logger.warning("Guardrail BLOCKED (%s): %s", guardrail_name, reason)
                return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        return None

    def _check_rate_limit(self, key: str, limit: int, guardrail_name: str) -> ValidationResult | None:
        """Sliding-window rate limit. Returns None if within limit."""
        now = time.time()
        window_start = now - 60.0

        if key not in self._rate_counters:
            self._rate_counters[key] = []

        # Prune old timestamps
        self._rate_counters[key] = [t for t in self._rate_counters[key] if t > window_start]

        if len(self._rate_counters[key]) >= limit:
            reason = f"Rate limit exceeded: {len(self._rate_counters[key])}/{limit} per minute for {key}"
            logger.warning("Guardrail BLOCKED (%s): %s", guardrail_name, reason)
            return ValidationResult(is_safe=False, layer=LAYER, blocked_reason=reason)

        self._rate_counters[key].append(now)
        return None
