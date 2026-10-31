import re

URL_RE = re.compile(r"https?://[^\s]+|www\.[^\s]+|\b[\w-]+(?:\.[\w-]+)*\.(?:com|in|co|xyz|top|net|org|info|icu|support)\b/?\S*")
URGENCY = ["immediately", "today", "within", "urgent", "block", "suspend", "expire"]

def run_detection(message: str, channel: str, claimed_identity: str | None = None,
                  urls: list | None = None):
    """Last-resort scorer. Links passed in `urls` (e.g. sent separately by the
    extension) are scored as well, not just links found in the text."""
    signals, score = [], 0
    low = (message or "").lower()

    for w in URGENCY:
        if w in low:
            signals.append({"type": "URGENT_LANGUAGE", "evidence": w, "severity": "HIGH"})
            score += 15
            break
    if "kyc" in low or "verify" in low:
        signals.append({"type": "CREDENTIAL_REQUEST", "evidence": "KYC/verify request", "severity": "HIGH"})
        score += 25

    all_urls = list(urls or [])
    for u in URL_RE.findall(message or ""):
        if u not in all_urls:
            all_urls.append(u)
    for url in all_urls:
        signals.append({"type": "SUSPICIOUS_URL", "evidence": url, "severity": "MEDIUM"})
        score += 30

    score = min(score, 100)
    level = "LOW" if score < 25 else "MODERATE" if score < 50 else "HIGH"
    return {
        "risk_score": score,
        "risk_level": level,
        "classification": "PHISHING" if score >= 70 else "LEGITIMATE" if score < 25 else "UNCERTAIN",
        "language": "auto",
        "signals": signals,
    }
