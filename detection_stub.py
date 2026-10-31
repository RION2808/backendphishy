import re

URL_RE = re.compile(r"https?://[^\s]+|\b\w+\.(?:com|in|co|xyz|top)/\S*")
URGENCY = ["immediately", "today", "within", "urgent", "block", "suspend", "expire"]

def run_detection(message: str, channel: str, claimed_identity: str | None):
    signals, score = [], 0
    low = message.lower()

    for w in URGENCY:
        if w in low:
            signals.append({"type": "URGENT_LANGUAGE", "evidence": w, "severity": "HIGH"})
            score += 15
            break
    if "kyc" in low or "verify" in low:
        signals.append({"type": "CREDENTIAL_REQUEST", "evidence": "KYC/verify request", "severity": "HIGH"})
        score += 25
    for url in URL_RE.findall(message):
        signals.append({"type": "SUSPICIOUS_URL", "evidence": url, "severity": "MEDIUM"})
        score += 25

    score = min(score, 100)
    level = "LOW" if score < 25 else "MODERATE" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
    return {
        "risk_score": score,
        "risk_level": level,
        "classification": "PHISHING" if score >= 50 else "LEGITIMATE" if score < 25 else "UNCERTAIN",
        "language": "auto",
        "signals": signals,
    }