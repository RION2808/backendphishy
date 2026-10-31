"""Builds the single JSON shape the browser extension displays."""



# Advice shown when the AI explanation is unavailable, matched to the risk level.
TIER_ADVICE = {
    "HIGH": [
        "Don't click the link, open attachments or reply to this message.",
        "Never share OTPs, passwords, PINs, card details or your address through it.",
        "Check the claim yourself by opening the official app or typing the company's website address directly.",
        "Delete the message, and report it (in India: cybercrime.gov.in or call 1930) if money or details were involved.",
    ],
    "MODERATE": [
        "Don't click the link or reply until you have verified the message.",
        "Check it through the company's official app or website, typed in yourself.",
        "Don't share personal or payment details through this message.",
    ],
    "LOW": [
        "Few warning signs were found, so no urgent action is needed.",
        "If you weren't expecting this message, check the sender through the official app or website before acting on it.",
    ],
    "INCONCLUSIVE": [
        "There isn't enough in this message to judge it either way.",
        "If it asks for money or details, verify the sender through a channel you already trust.",
    ],
}

# Always-appended generic lines from the scorer; too noisy for low-risk results.
GENERIC_SCORER_ADVICE = {
    "Never share OTPs, passwords, PINs or CVVs through unexpected messages.",
    "Do not open suspicious links to investigate them.",
    "Verify important requests through a known official contact channel.",
}


def _dedupe(items):
    seen, out = set(), []
    for item in items:
        if isinstance(item, str) and item.strip() and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def build_response(detection: dict, explanation: dict) -> dict:
    ai_ok = explanation.get("uncertainty") != "Explanation generated without AI."

    level = str(detection.get("risk_level", "")).upper()
    tier = list(TIER_ADVICE.get(level, TIER_ADVICE["INCONCLUSIVE"]))

    # Specific advice from the detectors (e.g. about shortened links).
    specific = [
        r for r in (detection.get("recommendations") or [])
        if r not in GENERIC_SCORER_ADVICE
    ]

    if ai_ok:
        recs = list(explanation.get("safe_recommendations") or [])
        recs += list(explanation.get("verification_steps") or [])
    else:
        recs = tier

    # Detector-specific advice only matters when something was flagged.
    if level in ("HIGH", "MODERATE"):
        recs += specific

    summary = explanation.get("short_summary") or explanation.get("explanation") or ""
    if ai_ok and explanation.get("explanation") and explanation.get("short_summary"):
        summary = f"{explanation['short_summary']} {explanation['explanation']}"

    if not ai_ok:
        level = str(detection.get("risk_level", "")).upper()
        summary = {
            "HIGH": "This message shows several strong signs of a scam. Don't click the link or reply.",
            "MODERATE": "This message has some warning signs. Verify it through an official channel before acting.",
            "LOW": "Few warning signs were found, but stay careful with unexpected requests.",
        }.get(level, "There isn't enough evidence for a reliable result. Verify the sender through an official channel.")

    findings = list(detection.get("findings") or [])
    if not findings:
        findings = [
            f"{s.get('type', 'SIGNAL')}: {s.get('evidence', '')}".strip()
            for s in detection.get("signals", [])
        ]

    return {
        **detection,
        **explanation,
        # Fields the extension reads directly:
        "score": int(detection.get("risk_score", 0) or 0),
        "summary": summary,
        "evidence": findings,
        "recommendations": _dedupe(recs)[:7],
        "ai_explanation": ai_ok,
    }
