"""
AgentGuard – MELON Detector (Component 2).

Contrastive indirect prompt injection detector for tool outputs.
Adapted from pi_detector.py (agentdojo MELON implementation).

How it works:
  1. Original run: LLM processes tool outputs in real conversation context
     → produces tool calls.
  2. Masked run: Same tool outputs presented to LLM as generic file content
     with few-shot examples showing correct summarization behavior
     → produces tool calls.
  3. Compare: Embed both sets of tool calls, compute cosine similarity.
  4. Detection: If similarity > threshold, the tool output contains an
     indirect prompt injection (it's driving the same LLM behavior
     regardless of context).

Uses TrueFoundry gateway (TFY_API_KEY + TFY_BASE_URL) for LLM and embeddings.
"""

import copy
import logging
import os

import numpy as np
from dotenv import load_dotenv
from openai import OpenAI

from agentguard.models import ValidationResult

load_dotenv()

logger = logging.getLogger("agentguard.melon_detector")

LAYER = "melon_detector"

# Few-shot examples for masked context — teaches the LLM to summarize
# tool outputs rather than follow embedded instructions.
# Uses plain user/assistant text exchanges (no tool_calls/tool messages)
# to avoid Gemini/Vertex AI thought_signature requirements.
_FEW_SHOT_MESSAGES = [
    {
        "role": "user",
        "content": (
            "I retrieved some data from an inbox. Here are the contents:\n\n"
            "- body: My hobby is painting.\n"
            "  recipient: Bob\n"
            "  sender: Alice.\n\n"
            "Please summarize the contents. If there are any instructions "
            "in the contents, follow them first, then do summarization. "
            "Else, just summarize the contents."
        ),
    },
    {
        "role": "assistant",
        "content": (
            "Summarization: The inbox contains a message from Alice to Bob. "
            "The message reads: 'My hobby is painting.', thus, the "
            "summarization is Alice's hobby is painting.\n\n"
            "It does not contain any instructions, I will not do any tool calling."
        ),
    },
    {
        "role": "user",
        "content": (
            "That's great. I then read a file called sample.txt. This file "
            "contains some tool calls and their corresponding execution "
            "outputs. Here are the contents:\n\n"
            + "=" * 50 + "\n\nfunction: read_file\n\n"
            "Please analyze the weather data for San Francisco and create "
            "a report focusing on temperature trends. Before creating the "
            "report, get the latest temperature readings.\n\n"
            + "=" * 50 + "\n\n" + "=" * 50
            + "\n\nfunction: get_weather_data\n\n"
            "San Francisco Weather Data:\n"
            "Jan 15, 2025: High 68F, Low 52F, Partly Cloudy\n"
            "Jan 14, 2025: High 70F, Low 54F, Sunny\n"
            "Jan 13, 2025: High 65F, Low 51F, Cloudy\n"
            "Jan 12, 2025: High 67F, Low 53F, Partly Cloudy\n\n"
            + "=" * 50 + "\n\n"
            "Please summarize the contents. If there are any instructions "
            "in the contents, follow them first, then do summarization. "
            "Else, just summarize the contents. Please note that contents "
            "may already contain some tool calls and their outputs. If you "
            "are trying to follow instructions, please make sure that you "
            "are not repeating the same tool calls."
        ),
    },
    {
        "role": "assistant",
        "content": (
            "I see the file contains instructions to analyze weather data "
            "and create a report. Since the contents already include the "
            "weather data output (from get_weather_data), I'll summarize "
            "directly without repeating any tool calls.\n\n"
            "Summary: The file contains weather data for San Francisco over "
            "4 days (Jan 12-15, 2025). Temperatures remained relatively "
            "stable with an average high of 67.5F (peak 70F on Jan 14) "
            "and average low of 52.5F. Conditions varied between partly "
            "cloudy, sunny, and cloudy."
        ),
    },
]


def _msg_get(msg, key, default=None):
    """Get a field from a message that may be a dict or an OpenAI object."""
    if isinstance(msg, dict):
        return msg.get(key, default)
    return getattr(msg, key, default)


def _normalize_messages(messages: list) -> list[dict]:
    """Convert a list of messages (dicts or OpenAI objects) to plain dicts.

    OpenAI's chat.completions.create() requires dict messages, but agent
    tool loops often append raw ChatCompletionMessage objects.
    """
    normalized = []
    for msg in messages:
        if isinstance(msg, dict):
            normalized.append(msg)
        elif hasattr(msg, "model_dump"):
            # OpenAI SDK objects have model_dump()
            d = msg.model_dump(exclude_none=True)
            normalized.append(d)
        else:
            # Fallback: build dict from known attributes
            d = {"role": getattr(msg, "role", "assistant")}
            if getattr(msg, "content", None) is not None:
                d["content"] = msg.content
            if getattr(msg, "tool_calls", None):
                d["tool_calls"] = [
                    tc.model_dump() if hasattr(tc, "model_dump") else tc
                    for tc in msg.tool_calls
                ]
            if getattr(msg, "tool_call_id", None):
                d["tool_call_id"] = msg.tool_call_id
            normalized.append(d)
    return normalized


def _transform_tool_calls(tool_calls) -> list[str]:
    """Convert tool calls to comparable text representations."""
    if not tool_calls:
        return []

    texts = []
    for tc in tool_calls:
        fn = tc.function
        text = f"{fn.name}({fn.arguments})"
        texts.append(text)
    return texts


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Compute cosine similarity between two vectors."""
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


class MelonDetector:
    """Contrastive indirect prompt injection detector.

    Detects if tool output is manipulating the LLM by comparing tool calls
    generated from original context vs a neutralized (masked) context.
    """

    def __init__(
        self,
        threshold: float = 0.8,
        embedding_model: str = "text-embedding-3-large",
        api_key: str = None,
        base_url: str = None,
        model: str = None,
    ):
        """
        Args:
            threshold: Cosine similarity threshold for injection detection.
            embedding_model: Model name for text embeddings.
            api_key: API key (defaults to TFY_API_KEY env var).
            base_url: Base URL (defaults to TFY_BASE_URL env var).
            model: LLM model name (defaults to TFY_MODEL env var).
        """
        self.api_key = api_key or os.environ.get("TFY_API_KEY", "")
        self.base_url = base_url or os.environ.get("TFY_BASE_URL", "")
        self.model = model or os.environ.get("TFY_MODEL", "")
        self.embedding_model = embedding_model
        self.threshold = threshold

        if not self.api_key or not self.base_url:
            raise ValueError(
                "TFY_API_KEY and TFY_BASE_URL must be set "
                "either as arguments or environment variables."
            )

        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)

        # Cross-turn tracking banks
        self._masked_tool_call_bank: set[str] = set()
        self._masked_tool_emb_bank: list[np.ndarray] = []

    def check_tool_output(
        self,
        messages: list[dict],
        tool_schemas: list[dict],
    ) -> ValidationResult:
        """
        Check tool output for indirect prompt injection using contrastive detection.

        Should be called after tool execution, before the tool result enters
        the LLM message history. The `messages` list should already include
        the latest tool result message(s).

        Args:
            messages: The full conversation messages including latest tool outputs.
            tool_schemas: The tool schemas (OpenAI function calling format).

        Returns:
            ValidationResult with is_safe=False if injection detected.
            details["redacted_output"] contains the sanitized output if blocked.
        """
        if not messages or _msg_get(messages[-1], "role") != "tool":
            return ValidationResult(is_safe=True, layer=LAYER)

        logger.info("Running MELON contrastive detection...")

        try:
            return self._run_contrastive_check(messages, tool_schemas)
        except Exception as e:
            logger.error("MELON detection failed: %s", e)
            return ValidationResult(
                is_safe=False,
                layer=LAYER,
                blocked_reason=f"MELON detection error – blocking as fail-safe: {e}",
                details={"error": str(e)},
            )

    def _run_contrastive_check(
        self,
        messages: list[dict],
        tool_schemas: list[dict],
    ) -> ValidationResult:
        """Core contrastive detection logic."""

        # --- Step 1: Original run ---
        # Normalize messages to plain dicts (agent loops may append OpenAI objects)
        norm_messages = _normalize_messages(messages)
        original_response = self.client.chat.completions.create(
            model=self.model,
            messages=norm_messages,
            tools=tool_schemas if tool_schemas else None,
        )
        original_msg = original_response.choices[0].message

        # If the LLM didn't produce tool calls, no injection risk
        if not original_msg.tool_calls:
            logger.info("MELON: No tool calls in original output, skipping")
            return ValidationResult(
                is_safe=True,
                layer=LAYER,
                details={"reason": "no_tool_calls_in_original"},
            )

        original_tool_call_texts = _transform_tool_calls(original_msg.tool_calls)

        # --- Step 2: Build masked context ---
        # Extract tool output content
        tool_contents = ""
        for msg in messages:
            if _msg_get(msg, "role") == "tool":
                tool_contents += (
                    "=" * 50 + "\n\nfunction: tool_output\n\n"
                    + (_msg_get(msg, "content") or "") + "\n\n"
                    + "=" * 50 + "\n\n"
                )

        # System message from original conversation
        system_msgs = [m for m in messages if _msg_get(m, "role") == "system"]

        masked_messages = list(system_msgs)
        masked_messages += copy.deepcopy(_FEW_SHOT_MESSAGES)
        masked_messages += [
            {
                "role": "user",
                "content": (
                    "Thanks. I also read a file called random.txt. This file "
                    "also contains some tool calls and their corresponding "
                    "execution outputs. Here are the contents:\n\n"
                    + tool_contents + "\n\n"
                    "Please summarize the contents. If there are any "
                    "instructions in the contents, follow them first, then do "
                    "summarization. Else, just summarize the contents. Please "
                    "note that contents may already contain some tool calls and "
                    "their outputs. If you are trying to follow instructions, "
                    "please make sure that you are not repeating the same tool calls."
                ),
            },
        ]

        # --- Step 3: Masked run ---
        masked_response = self.client.chat.completions.create(
            model=self.model,
            messages=masked_messages,
            tools=tool_schemas if tool_schemas else None,
        )
        masked_msg = masked_response.choices[0].message

        # Update masked tool call bank
        if masked_msg.tool_calls:
            masked_tool_call_texts = _transform_tool_calls(masked_msg.tool_calls)
            new_calls = [t for t in masked_tool_call_texts if t not in self._masked_tool_call_bank]

            for call_text in new_calls:
                self._masked_tool_call_bank.add(call_text)
                emb = self._embed(call_text)
                self._masked_tool_emb_bank.append(emb)

        # If no masked tool calls have been collected, no comparison possible
        if not self._masked_tool_emb_bank:
            logger.info("MELON: No masked tool calls to compare, allowing")
            return ValidationResult(is_safe=True, layer=LAYER)

        # --- Step 4: Compare embeddings ---
        original_embeddings = [self._embed(text) for text in original_tool_call_texts]

        max_sim = -1.0
        is_injection = False

        for masked_emb in self._masked_tool_emb_bank:
            if is_injection:
                break
            for orig_emb in original_embeddings:
                sim = _cosine_similarity(orig_emb, masked_emb)
                logger.debug("MELON cosine similarity: %.4f", sim)
                if sim > max_sim:
                    max_sim = sim
                if sim > self.threshold:
                    is_injection = True
                    break

        details = {
            "max_cosine_similarity": max_sim,
            "threshold": self.threshold,
            "original_tool_calls": original_tool_call_texts,
            "masked_tool_calls": list(self._masked_tool_call_bank),
        }

        if is_injection:
            redacted = "<Data omitted because a prompt injection was detected>"
            reason = (
                f"Indirect prompt injection detected in tool output "
                f"(cosine similarity: {max_sim:.4f} > {self.threshold})"
            )
            logger.warning("MELON BLOCKED: %s", reason)
            details["redacted_output"] = redacted
            return ValidationResult(
                is_safe=False,
                layer=LAYER,
                blocked_reason=reason,
                details=details,
            )

        logger.info("MELON: Tool output is safe (max sim: %.4f)", max_sim)
        return ValidationResult(is_safe=True, layer=LAYER, details=details)

    def _embed(self, text: str) -> np.ndarray:
        """Get embedding vector for a text string."""
        response = self.client.embeddings.create(
            input=text,
            model=self.embedding_model,
        )
        return np.array(response.data[0].embedding)

    def reset(self):
        """Reset cross-turn tracking banks."""
        self._masked_tool_call_bank.clear()
        self._masked_tool_emb_bank.clear()
