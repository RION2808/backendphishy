"""Builds the single JSON shape the browser extension displays."""

from i18n import TIER_ADVICE, SUMMARY

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


def build_response(detection: dict, explanation: dict, lang: str = "en") -> dict:
    lang = lang if lang in TIER_ADVICE else "en"
    ai_ok = bool(explanation.get("ai_generated", False))

    level = str(detection.get("risk_level", "")).upper()
    if level not in TIER_ADVICE[lang]:
        level = "INCONCLUSIVE"
    tier = list(TIER_ADVICE[lang][level])

    # Detector-specific advice (already translated by detection.py), minus the
    # generic lines. English-only filter is applied on the English originals.
    specific = [
        t for t, en in zip(detection.get("recommendations") or [],
                           detection.get("recommendations_en") or [])
        if en not in GENERIC_SCORER_ADVICE
    ] if detection.get("recommendations_en") else [
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
        summary = SUMMARY[lang][level]

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
        "language": lang,
    }
