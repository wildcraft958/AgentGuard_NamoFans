"""
AgentGuard – Fast Offline Injection Detection (Component 0 / L1 pre-filter).

33 compiled regexes catch the most common prompt-injection patterns in pure
Python with zero network latency. This runs *before* the Azure Prompt Shields
API call to reduce API usage and add offline resilience.

Adapted from claude-guard's _INJECTION_PATTERNS + inject_detect() method.
"""

import re

_INJECTION_PATTERNS = [
    # Classic override directives
    r"ignore\s+(all\s+)?previous\s+instructions?",
    r"disregard\s+(all\s+)?previous\s+instructions?",
    r"forget\s+(all\s+)?previous\s+instructions?",
    r"override\s+(all\s+)?previous\s+instructions?",
    r"ignore\s+your\s+(system\s+)?(prompt|instructions?|guidelines?|rules?)",
    r"do\s+not\s+follow\s+(your\s+)?(previous\s+)?instructions?",
    # Role/persona hijacking
    r"you\s+are\s+now\s+(a\s+|an\s+)?(new|different|evil|unrestricted|jailbroken|free)",
    r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(a\s+|an\s+)?(DAN|evil|unrestricted|uncensored|jailbroken)",
    r"pretend\s+(you\s+are|to\s+be)\s+(a\s+|an\s+)?(DAN|evil|unrestricted|uncensored)",
    r"simulate\s+(being\s+)?(a\s+|an\s+)?(DAN|evil|unrestricted|AI\s+without\s+(restrictions?|rules?))",
    r"roleplay\s+as\s+(a\s+|an\s+)?(evil|malicious|unrestricted|uncensored)",
    r"enter\s+(developer|jailbreak|DAN|god|unrestricted)\s+mode",
    r"enable\s+(developer|jailbreak|DAN|unrestricted)\s+mode",
    # System prompt extraction
    r"(print|repeat|show|reveal|output|display|tell\s+me|what\s+is)\s+(your\s+)?(system\s+prompt|initial\s+prompt|original\s+instructions?|hidden\s+instructions?)",
    r"(ignore|bypass|skip)\s+(the\s+)?(system\s+)?(prompt|instructions?|guidelines?|safeguards?|restrictions?)",
    r"what\s+(were\s+)?you\s+(told|instructed|programmed)\s+to\s+(do|say|avoid)",
    # Injection markers / delimiters
    r"<\s*(system|assistant|human|user|prompt|instruction)\s*>",
    r"\[\s*(system|assistant|human|user|prompt|instruction)\s*\]",
    r"###\s*(system|instruction|new\s+task|override)",
    r"---\s*(system|instruction|new\s+task|override)\s*---",
    r"SYSTEM\s*:\s*(override|ignore|new\s+instructions?|you\s+are)",
    # Jailbreak keywords
    r"\bDAN\b",  # Do Anything Now
    r"jailbreak",
    r"do\s+anything\s+now",
    r"without\s+(any\s+)?(restrictions?|filters?|limitations?|guidelines?|rules?)",
    r"no\s+(restrictions?|filters?|limitations?|guidelines?|rules?)\s+apply",
    # Confidentiality bypass
    r"(you\s+can|you\s+are\s+allowed\s+to)\s+(say|output|write|generate)\s+anything",
    r"(ignore|bypass)\s+(content\s+)?safety",
    r"(ignore|bypass)\s+(your\s+)?(ethical|moral)\s+(guidelines?|constraints?|principles?)",
    # Prompt leaking
    r"(leak|exfiltrate|extract|dump)\s+(the\s+)?(system\s+)?prompt",
    r"translate\s+(the\s+)?(above|previous|following).*to\s+(base64|hex|rot13)",
    # Continuation / completion attacks
    r"complete\s+the\s+following\s+(ignoring|without)\s+(your\s+)?(safety|content|ethical)",
    # Token/encoding tricks
    r"base64\s+decode\s+the\s+following\s+(and\s+execute|and\s+run|and\s+output)",
]

_COMPILED: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE | re.DOTALL) for p in _INJECTION_PATTERNS
]


def fast_inject_detect(text: str) -> tuple[bool, str | None]:
    """
    Fast offline prompt-injection detector.

    Scans text against 33 compiled regex patterns that cover common injection
    techniques: override directives, role hijacking, system prompt extraction,
    jailbreak keywords, and delimiter injection.

    Args:
        text: The input text to scan.

    Returns:
        (True, pattern_string) if injection detected.
        (False, None) if text appears clean.
    """
    if not text or not text.strip():
        return False, None

    for pat in _COMPILED:
        if pat.search(text):
            return True, pat.pattern

    return False, None
