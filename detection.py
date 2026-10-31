import re
from trustlens_security import analyze_security
from detection_stub import run_detection as stub_detection

# Full URLs and www. links.
URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)

# Bare domains such as "fedex-package-redelivery-support.in", which scam
# messages often use without any http:// prefix.
LINK_TLDS = (
    "com|net|org|info|biz|co|io|in|me|us|uk|de|fr|ru|cn|app|dev|ai|xyz|top|"
    "site|online|club|shop|store|link|click|live|life|support|help|icu|vip|"
    "work|tech|cloud|page|pro|tv|ly|cc|tk|ml|ga|cf|gq|bank|finance|email|"
    "services|world|today|digital|sbi|gov|edu"
)
BARE_DOMAIN_PATTERN = re.compile(
    r"(?<![@\w./-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:" + LINK_TLDS + r")"
    r"(?![\w@-])(?::\d+)?(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)

HIGH_RULES = {"credential_request", "financial_request", "delivery_scam"}
HIGH_URL_FLAGS = {
    "ip_address_host", "embedded_credentials", "possible_lookalike_domain",
    "visible_destination_mismatch", "at_symbol_authority",
    "brand_in_unofficial_domain",
}
LEVEL_MAP = {"LOW": "LOW", "MEDIUM": "MODERATE", "HIGH": "HIGH",
             "INCONCLUSIVE": "INCONCLUSIVE"}

_TRAILING = ".,;:!?)]}'\""


def _clean(raw: str) -> str:
    return raw.rstrip(_TRAILING)


def extract_urls(message: str, extra_urls=None) -> list:
    """Find links in the message text and merge in any links sent separately."""
    found = []

    def add(url):
        url = _clean((url or "").strip())
        if url and url not in found:
            found.append(url)

    for item in extra_urls or []:
        add(item.get("url") if isinstance(item, dict) else item)

    text = message or ""
    for raw in URL_PATTERN.findall(text):
        add(raw)
    for raw in BARE_DOMAIN_PATTERN.findall(text):
        cleaned = _clean(raw)
        # Skip bare domains already covered by a longer full URL.
        if not any(cleaned in existing for existing in found):
            add(cleaned)

    visible = {}
    for item in extra_urls or []:
        if isinstance(item, dict) and item.get("url"):
            visible[_clean(item["url"].strip())] = item.get("visible_text", "") or ""

    return [{"url": u, "visible_text": visible.get(u, "")} for u in found]


def run_detection(message: str, channel: str, claimed_identity=None,
                  nlp_result=None, extra_urls=None):
    try:
        result = analyze_security(
            message=message,
            urls=extract_urls(message, extra_urls),
            nlp_result=nlp_result or {},
        )
    except Exception as e:
        print("Detection error, using stub:", e)
        return stub_detection(message, channel, claimed_identity)

    signals = []
    findings = []
    for item in result["evidence"]:
        if item["source"] == "rule_engine":
            matched = ", ".join(str(m) for m in item["matched_text"])
            signals.append({
                "type": item["rule"].upper(),
                "evidence": matched,
                "severity": "HIGH" if item["rule"] in HIGH_RULES else "MEDIUM",
            })
            findings.append(f"{item['description']} (matched: {matched})")
        elif item["source"] == "url_analyzer":
            findings.append(f"{item['description']} [{item.get('url', '')}]")
        elif item["source"] in ("risk_scorer",):
            findings.append(item["description"])

    for u in result["url_analysis"]:
        for flag in u.get("findings", []):
            signals.append({
                "type": flag.upper(),
                "evidence": u.get("url", ""),
                "severity": "HIGH" if flag in HIGH_URL_FLAGS else "MEDIUM",
            })

    score = int(result["score"])
    level = result["risk_level"]
    if level == "INCONCLUSIVE":
        classification = "UNCERTAIN"
    elif score >= 70:
        classification = "PHISHING"
    elif score < 35:
        classification = "LEGITIMATE"
    else:
        classification = "UNCERTAIN"

    return {
        "risk_score": score,
        "risk_level": LEVEL_MAP.get(level, level),
        "classification": classification,
        "language": "auto",
        "signals": signals,
        "findings": findings,
        "assessment_status": result["assessment_status"],
        "components": result["components"],
        "link_status": result["link_status"],
        "recommendations": result["recommendations"],
    }
