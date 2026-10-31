import re
from nlp_inference import predict_message
from trustlens_security import analyze_security
from detection_stub import run_detection as stub_detection
from i18n import localize_rule, localize_url_finding, localize_detector_advice

# Full URLs and www. links.
URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"'\u0964\u0965]+", re.IGNORECASE)

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
    "brand_in_unofficial_domain", "scam_keywords_in_domain",
}
LEVEL_MAP = {"LOW": "LOW", "MEDIUM": "MODERATE", "HIGH": "HIGH",
             "INCONCLUSIVE": "INCONCLUSIVE"}

_TRAILING = ".,;:!?)]}'\"\u0964\u0965"


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


def strip_urls(message: str, urls: list) -> str:
    """Remove links from the text so the wording rules only read the prose.

    Otherwise words inside a domain (e.g. "redelivery" in
    fedex-package-redelivery-support.in) get counted by the text rules AND by
    the URL analyzer.
    """
    text = message or ""
    # Longest first so a full URL is removed before any bare domain inside it.
    for u in sorted((item["url"] for item in urls), key=len, reverse=True):
        text = text.replace(u, " ")
    text = URL_PATTERN.sub(" ", text)
    return BARE_DOMAIN_PATTERN.sub(" ", text)


def run_detection(message: str, channel: str, claimed_identity=None,
                  nlp_result=None, extra_urls=None, lang: str = "en"):

    urls = extract_urls(message, extra_urls)

    # Run BERT automatically if no NLP result was supplied.
    if nlp_result is None:
        try:
            nlp_result = predict_message(message)
            print("NLP prediction:", nlp_result)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print("NLP inference failed:", e)
            nlp_result = {}

    try:
        result = analyze_security(
            message=strip_urls(message, urls),
            urls=urls,
            nlp_result=nlp_result or {},
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        print("Detection error, using stub:", e)
        # Pass the links along too, so the fallback still scores them.
        return stub_detection(message, channel, claimed_identity,
                              urls=[u["url"] for u in urls])

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
            desc = localize_rule(item["rule"], item["description"], lang)
            findings.append(f"{desc} ({matched})")
        elif item["source"] == "risk_scorer":
            findings.append(item["description"])

    # Link findings: evidence lines line up 1:1 with finding codes, so each
    # one can be translated by its code.
    for u in result["url_analysis"]:
        codes = u.get("findings", [])
        lines = u.get("evidence", [])
        for i, flag in enumerate(codes):
            english = lines[i] if i < len(lines) else flag
            findings.append(
                f"{localize_url_finding(flag, english, lang)} [{u.get('url', '')}]"
            )
            signals.append({
                "type": flag.upper(),
                "evidence": u.get("url", ""),
                "severity": "HIGH" if flag in HIGH_URL_FLAGS else "MEDIUM",
            })

    score = int(result["score"])
    level = result["risk_level"]

    assessment_status = result["assessment_status"]

    if assessment_status != "COMPLETE" or level == "INCONCLUSIVE":
        classification = "UNCERTAIN"

    elif score >= 70:
        classification = "PHISHING"

    elif score >= 35:
        classification = "UNCERTAIN"

    elif (
        nlp_result
        and nlp_result.get("label") == "phishing"
    ):
        classification = "UNCERTAIN"

    elif signals:
        classification = "UNCERTAIN"

    else:
        classification = "LEGITIMATE"

    return {
        "risk_score": score,
        "risk_level": LEVEL_MAP.get(level, level),
        "classification": classification,
        "language": lang,
        "signals": signals,
        "findings": findings,
        "assessment_status": result["assessment_status"],
        "components": result["components"],
        "url_analysis": [
            {"url": u.get("url"), "score": u.get("score", 0),
             "findings": u.get("findings", [])}
            for u in result["url_analysis"]
        ],
        "link_status": result["link_status"],
        "recommendations": [
            t for t in (localize_detector_advice(r, lang)
                        for r in result["recommendations"]) if t
        ],
        "recommendations_en": result["recommendations"],
    }
