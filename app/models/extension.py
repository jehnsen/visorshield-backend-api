"""
Pydantic models for the browser-extension surface.

These mirror the contract the extension already codes against (see
``dev/mock-server/server.mjs`` in the visorshield-browser-extension repo).
Response field names are part of that contract and are validated with Zod on
the extension side — renaming one here breaks the client, which fails closed.

Why this is a separate surface from ``/v1/chat/completions``: the proxy masks
transparently and forwards to the provider itself. The extension never forwards
anything — VisorShield does not sit in the network path of chatgpt.com. It
returns the masked prompt to the content script, which types it into the page.
That inverts one thing fundamentally: the user SEES the masking and must accept
it, so the response has to carry per-entity detail the proxy never needed.
"""
from pydantic import BaseModel, Field
from typing import Dict, List, Literal, Optional


# ── Scan ─────────────────────────────────────────────────────────────────────

class ExtensionScanRequest(BaseModel):
    """A prompt captured from a web chat composer, before it is sent."""
    prompt: str
    # Raw conversation id from the page URL; null for a brand-new chat.
    conversation_id: Optional[str] = None
    site: Literal["chatgpt"] = "chatgpt"


class ScanEntity(BaseModel):
    """
    One detected entity. ``original`` is what makes rehydration possible on the
    device, and is the single most sensitive field this service ever emits — it
    is returned ONLY to the extension that submitted the prompt, is never
    persisted here, and never reaches an audit row or a log line.
    """
    type: str
    placeholder: str
    original: str


class ExtensionScanResponse(BaseModel):
    transaction_id: str
    status: Literal["clean", "masked"]
    risk_level: Literal["low", "medium", "high"]
    masked_prompt: str
    entities: List[ScanEntity]
    summary: Dict[str, int]
    prior_flags_this_month: int
    policy_profile: str


# ── Response scan ────────────────────────────────────────────────────────────

class ExtensionResponseScanRequest(BaseModel):
    """Assistant output pulled from the page, audited when policy says to."""
    transaction_id: str
    text: str


class NewEntity(BaseModel):
    """Entity type + placeholder only. Never carries the original value."""
    type: str
    placeholder: str


class ExtensionResponseScanResponse(BaseModel):
    new_entities: List[NewEntity]


# ── Policy ───────────────────────────────────────────────────────────────────

class ExtensionPolicy(BaseModel):
    """
    Device-side enforcement policy, cached by the background worker.

    ``fail_mode`` is the one field with teeth: "closed" means the extension
    refuses to send when it cannot reach this service. Defaulting it to "open"
    anywhere would silently disable the product.
    """
    fail_mode: Literal["closed", "open"] = "closed"
    review_mode: Literal["always", "on_pii", "never"] = "on_pii"
    auto_mask: bool = False
    allow_override: bool = False
    uploads: Literal["block", "warn", "allow"] = "block"
    voice: Literal["block", "warn", "allow"] = "block"
    audit_responses: bool = False
    rehydrate_code: bool = False
    scan_timeout_ms: int = Field(default=8000, ge=1000, le=30000)
    mode: Literal["compliance", "coaching"] = "compliance"


# ── Events ───────────────────────────────────────────────────────────────────

EventType = Literal[
    "masked_sent",
    "clean_sent",
    "blocked",
    "cancelled_after_review",
    "edited_after_review",
    "override_requested",
    "upload_blocked",
    "voice_blocked",
    "adapter_broken",
    "scan_failed",
    "signed_out_send_attempt",
]


class ExtensionEvent(BaseModel):
    """
    Metadata-only telemetry. The extension's own mock server hard-fails any
    event carrying prompt text, and this model does the same.

    ``extra="forbid"`` is the load-bearing part, not decoration. Pydantic's
    default is to silently DROP unknown fields, so an event carrying a
    ``prompt`` key would have been accepted with a 202 and the caller would
    have had every reason to think text telemetry was supported. Rejecting the
    batch makes the privacy contract enforceable instead of merely documented.
    """
    model_config = {"extra": "forbid"}

    type: EventType
    transaction_id: Optional[str] = None
    entity_counts: Optional[Dict[str, int]] = None
    category: Optional[str] = None
    missing: Optional[List[str]] = None
    dom_hash: Optional[str] = None
    ext: Optional[str] = None
    size_bytes: Optional[int] = None
    client_ts: str


class ExtensionEventBatch(BaseModel):
    events: List[ExtensionEvent] = Field(default_factory=list, max_length=100)


class ExtensionEventAck(BaseModel):
    accepted: int


# ── Heartbeat ────────────────────────────────────────────────────────────────

class ExtensionHeartbeatRequest(BaseModel):
    device_id: str
    extension_version: Optional[str] = None


class ExtensionHeartbeatResponse(BaseModel):
    ok: bool = True
