"""Turn Evidence into ranked plain-language reasons and one recommended action. No generation."""

from app.schemas import Evidence

MAX_REASONS = 5
SOURCE_RANK = {"rule": 1.0, "tier1": 0.9, "model": 0.7, "llm": 0.8}

ACTIONS = {
    "SCAM": {
        "otp_theft": "Do not share any OTP or PIN. Block the sender and report at cybercrime.gov.in or call 1930.",
        "upi_trap": "Do not scan the QR or enter your UPI PIN — you never need a PIN to receive money. Report on 1930.",
        "kyc_freeze": "Do not click the link. Update KYC only in your bank's official app or branch. Report at cybercrime.gov.in.",
        "invoice_fraud": "Do not pay. Confirm the bank-detail change by calling the vendor on a number you already have.",
        "fake_job": "Do not pay any fee or join the chat. Genuine employers never charge to hire you. Report on 1930.",
        "impersonation": "Do not call back or join any video call. Real police/officials never demand money or calls like this. Report on 1930.",
        "_default": "Do not click links, reply or call back. Block the sender and report at cybercrime.gov.in or call 1930.",
    },
    "SUSPICIOUS": {"_default": "Be careful: don't click links or share details until you verify through the official app or website."},
    "SAFE": {"_default": "No scam signs found. Still, never share OTPs, PINs or passwords with anyone."},
}


def _topic(e: Evidence) -> str:
    """Evidence about the same thing collapses to one sentence (e.g. one per URL)."""
    if e.id.startswith("url.") and "url" in e.detail:
        return f"url:{e.detail['url']}"
    return e.id


def explain(evidence: list[Evidence], verdict: str, category: str | None) -> tuple[list[str], str]:
    if verdict == "SAFE":
        chosen = [e for e in evidence if e.reason and e.weight < 0]
        chosen.sort(key=lambda e: e.weight)
    else:
        chosen = [e for e in evidence if e.reason and e.weight >= 0.3]
        chosen.sort(key=lambda e: (e.floor is not None, e.floor or 0, e.weight * SOURCE_RANK.get(e.source, 0.5)), reverse=True)

    reasons: list[str] = []
    seen_topics: set[str] = set()
    seen_text: set[str] = set()
    for e in chosen:
        topic = _topic(e)
        if topic in seen_topics or e.reason in seen_text:
            continue
        seen_topics.add(topic)
        seen_text.add(e.reason)
        reasons.append(e.reason)
        if len(reasons) == MAX_REASONS:
            break

    if verdict == "SAFE" and not reasons:
        reasons.append("No links, sender tricks or scam language were found.")

    actions = ACTIONS[verdict]
    action = actions.get(category or "", actions["_default"])
    return reasons, action
