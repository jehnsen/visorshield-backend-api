from typing import Tuple

# Pricing per 1M tokens (USD), as of known rates
PRICING_TABLE = {
    "gpt-4o": {"input": 5.00, "output": 15.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4-turbo": {"input": 10.00, "output": 30.00},
    "claude-sonnet-4-5": {"input": 3.00, "output": 15.00},
    "claude-haiku-4-5": {"input": 0.80, "output": 4.00},
    "claude-opus-4-5": {"input": 15.00, "output": 75.00},
}

# Cheap routing thresholds
CHEAP_TOKEN_THRESHOLD = 500
CHEAP_COMPLEXITY_THRESHOLD = 0.4

COMPLEXITY_KEYWORDS = [
    # Spec keywords (CLAUDE.md "LLM Cost Routing Rules") — presence of any one of
    # these is enough to keep a request off the cheap model.
    "analyze", "compare", "summarize", "generate", "explain in detail",
    # Additional high-effort signals
    "synthesize", "reason", "evaluate", "step by step", "comprehensive",
    "elaborate", "critique", "pros and cons", "write a report", "research",
    "translate",
]

CHEAP_MODEL_MAP = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-haiku-4-5",
}


def calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    pricing = PRICING_TABLE.get(model)
    if not pricing:
        return 0.0
    input_cost = (input_tokens / 1_000_000) * pricing["input"]
    output_cost = (output_tokens / 1_000_000) * pricing["output"]
    return round(input_cost + output_cost, 8)


def estimate_prompt_tokens(messages: list) -> int:
    """Rough token estimate: ~4 chars per token."""
    total_chars = 0
    for msg in messages:
        if isinstance(msg.content, str):
            total_chars += len(msg.content)
        elif isinstance(msg.content, list):
            for part in msg.content:
                if isinstance(part, dict) and part.get("type") == "text":
                    total_chars += len(part.get("text", ""))
    return max(1, total_chars // 4)


def compute_complexity_score(messages: list) -> float:
    """Heuristic complexity score [0.0, 1.0] based on keyword presence."""
    text = ""
    for msg in messages:
        if isinstance(msg.content, str):
            text += msg.content.lower()
        elif isinstance(msg.content, list):
            for part in msg.content:
                if isinstance(part, dict) and part.get("type") == "text":
                    text += part.get("text", "").lower()

    hits = sum(1 for kw in COMPLEXITY_KEYWORDS if kw in text)
    # Each matched keyword contributes 0.4, so a single strong keyword
    # (e.g. "analyze this contract") reaches CHEAP_COMPLEXITY_THRESHOLD and the
    # request is kept on the full model.
    return min(1.0, hits * CHEAP_COMPLEXITY_THRESHOLD)


def should_use_cheap_model(messages: list) -> Tuple[bool, str]:
    """Returns (use_cheap, reason_string)."""
    token_count = estimate_prompt_tokens(messages)
    complexity = compute_complexity_score(messages)

    if token_count < CHEAP_TOKEN_THRESHOLD and complexity < CHEAP_COMPLEXITY_THRESHOLD:
        return True, f"low_complexity_short_prompt(tokens={token_count},complexity={complexity:.2f})"
    return False, f"normal_routing(tokens={token_count},complexity={complexity:.2f})"
