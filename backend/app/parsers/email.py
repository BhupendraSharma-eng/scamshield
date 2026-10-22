"""Normalize raw and simple email input into :class:`Envelope` objects."""

from __future__ import annotations

import re
from email import policy
from email.message import Message
from email.parser import BytesParser, Parser

from bs4 import BeautifulSoup

from app.schemas import Envelope, Link


_URL_RE = re.compile(
    r"(?i)(?:https?://|www\.)[^\s<>\"']+|"
    r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|org|net|in|co\.in|gov\.in|bank\.in|sbi|io|ai|app|dev|me|ly|co|xyz|top|online|site)"
    r"(?:/[^\s<>\"']*)?"
)
_TRAILING = ".,;:!?)]}>'\""


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _urls_in_text(text: str) -> list[str]:
    return _unique([match.group(0).rstrip(_TRAILING) for match in _URL_RE.finditer(text)])


def _html_content(html: str) -> tuple[str, list[Link]]:
    soup = BeautifulSoup(html, "html.parser")
    links = [
        Link(text=anchor.get_text(" ", strip=True), href=str(anchor.get("href", "")).strip())
        for anchor in soup.find_all("a", href=True)
        if str(anchor.get("href", "")).strip()
    ]
    return soup.get_text(" ", strip=True), links


def _payload_text(part: Message) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError, AttributeError):
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        return payload if isinstance(payload, str) else ""


def _headers(message: Message) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in message.items():
        rendered = str(value)
        if key in result:
            result[key] += "\n" + rendered
        else:
            result[key] = rendered
    return result


def _normalize_message(message: Message) -> Envelope:
    attachments: list[str] = []
    plain_parts: list[str] = []
    html_parts: list[str] = []

    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename:
            attachments.append(str(filename))
        if disposition == "attachment":
            continue
        content_type = part.get_content_type().lower()
        if content_type == "text/plain":
            plain_parts.append(_payload_text(part))
        elif content_type == "text/html":
            html_parts.append(_payload_text(part))

    links: list[Link] = []
    html_texts: list[str] = []
    for html in html_parts:
        clean_text, found_links = _html_content(html)
        html_texts.append(clean_text)
        links.extend(found_links)

    text = "\n".join(part.strip() for part in plain_parts if part.strip())
    if not text:
        text = "\n".join(part for part in html_texts if part)
    hrefs = [link.href for link in links]
    return Envelope(
        channel="email",
        sender=str(message.get("From", "")) or None,
        subject=str(message.get("Subject", "")) or None,
        text=text,
        urls=_unique(hrefs + _urls_in_text(text)),
        links=links,
        headers=_headers(message),
        attachments=_unique(attachments),
        headers_available=True,
    )


def parse_raw_email(raw: str | bytes) -> Envelope:
    """Parse a complete RFC email, falling back safely for malformed input."""

    try:
        if isinstance(raw, bytes):
            message = BytesParser(policy=policy.default).parsebytes(raw)
        else:
            message = Parser(policy=policy.default).parsestr(raw)
        return _normalize_message(message)
    except Exception:
        text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
        return Envelope(channel="email", text=text)


def parse_simple_email(sender: str | None, subject: str | None, body: str) -> Envelope:
    """Normalize form/JSON email fields when original headers are unavailable."""

    looks_html = bool(re.search(r"(?is)<(?:html|body|a|p|div|br)\b", body))
    text = body
    links: list[Link] = []
    if looks_html:
        text, links = _html_content(body)
    return Envelope(
        channel="email",
        sender=sender,
        subject=subject,
        text=text,
        urls=_unique([link.href for link in links] + _urls_in_text(text)),
        links=links,
        headers_available=False,
    )
