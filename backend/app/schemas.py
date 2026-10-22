"""Shared data types for the ScamShield backend. Every analyzer emits `Evidence`."""

from typing import Any, Literal

from pydantic import BaseModel, Field

Channel = Literal["sms", "email", "url"]
EvidenceSource = Literal["rule", "model", "tier1", "llm"]


class Link(BaseModel):
    """A hyperlink found in an email: what the user sees vs where it really goes."""

    text: str
    href: str


class Envelope(BaseModel):
    """Channel-agnostic normalized input produced by the parsers."""

    channel: Channel
    sender: str | None = None          # SMS sender ID / phone, or email From header (raw)
    subject: str | None = None
    text: str = ""                      # cleaned body text ("" for url channel)
    urls: list[str] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)      # email <a> tags
    headers: dict[str, str] = Field(default_factory=dict)  # email headers, original casing of keys
    attachments: list[str] = Field(default_factory=list)  # filenames
    headers_available: bool = False     # True only when a full .eml/raw email was parsed


class Evidence(BaseModel):
    """One signal. Fusion and explanation operate generically on lists of these."""

    id: str                             # dotted id, e.g. "url.lookalike", "hdr.spf_fail", "t1.asks_secret"
    source: EvidenceSource
    weight: float                       # -1..1; positive = suggests scam, negative = suggests safe
    floor: float | None = None          # minimum final risk if this evidence is present
    reason: str                         # plain-language sentence shown to the user ("" = don't show)
    detail: dict[str, Any] = Field(default_factory=dict)  # raw values for UI/debug
