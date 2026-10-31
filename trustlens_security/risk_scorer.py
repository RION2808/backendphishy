
import math

from .url_analyzer import analyze_urls
from .rule_engine import analyze_rules


# Prototype weights. These are not experimentally calibrated.
BASE_WEIGHTS = {
    "nlp": 0.40,
    "rules": 0.30,
    "urls": 0.30,
}

# Experimental bonus for strong agreement across all three components.
CORROBORATION_BONUS = 15


def normalize_nlp_result(nlp_result: dict) -> tuple[int | None, list[str]]:
    """Convert NLP output into a 0-100 risk score."""

    if not isinstance(nlp_result, dict) or not nlp_result:
        return None, ["NLP result is unavailable."]

    label = str(nlp_result.get("label", "")).strip().lower()

    if label not in {"phishing", "legitimate", "uncertain"}:
        return None, ["NLP label is missing or unsupported."]

    try:
        confidence = float(nlp_result.get("confidence"))
    except (TypeError, ValueError):
        return None, ["NLP confidence is missing or invalid."]

    if not math.isfinite(confidence) or not 0 <= confidence <= 1:
        return None, ["NLP confidence is outside the valid range."]

    if label == "uncertain":
        return None, ["NLP classifier is uncertain."]

    if label == "phishing":
        return round(confidence * 100), []

    return round((1 - confidence) * 100), []


def calculate_url_score(url_results: list[dict]) -> int | None:
    """Use the highest individual URL score."""

    if not url_results:
        return None

    scores = []

    for item in url_results:
        try:
            score = int(item.get("score", 0))
            scores.append(max(0, min(100, score)))
        except (TypeError, ValueError, AttributeError):
            continue

    return max(scores) if scores else None


def calculate_final_score(components: dict) -> int:
    """
    Combine the available component scores.

    With an NLP score, use the weighted average of the available components.
    Without one (the current default), a weighted average would dilute a
    strong signal with an absent one, so independent rule and URL evidence is
    combined as a noisy-OR instead: 1 - (1 - r)(1 - u). One strong component
    still counts fully, and agreeing components reinforce each other.
    """

    nlp = components.get("nlp_score")
    rules = components.get("rule_score")
    urls = components.get("url_score")

    if nlp is None:
        parts = [s for s in (rules, urls) if s is not None]

        if not parts:
            return 0

        remaining = 1.0
        for part in parts:
            remaining *= 1 - max(0, min(100, part)) / 100

        return round((1 - remaining) * 100)

    available = {"nlp": nlp, "rules": rules, "urls": urls}

    weighted_total = 0
    available_weight = 0

    for name, score in available.items():
        if score is None:
            continue

        weight = BASE_WEIGHTS[name]
        weighted_total += score * weight
        available_weight += weight

    if available_weight == 0:
        return 0

    return round(weighted_total / available_weight)


def calculate_corroboration_bonus(components: dict) -> int:
    """
    Reward strong agreement across independent detection components.

    This is a prototype heuristic, not a statistically calibrated rule.
    """

    nlp_score = components.get("nlp_score")
    rule_score = components.get("rule_score")
    url_score = components.get("url_score")

    if (
        nlp_score is not None
        and rule_score is not None
        and url_score is not None
        and nlp_score >= 80
        and rule_score >= 30
        and url_score >= 25
    ):
        return CORROBORATION_BONUS

    return 0


def get_risk_level(score: int, inconclusive: bool = False) -> str:
    """Assign a prototype risk category."""

    if inconclusive:
        return "INCONCLUSIVE"

    if score >= 70:
        return "HIGH"

    if score >= 35:
        return "MEDIUM"

    return "LOW"


def analyze_security(
    message: str,
    urls: list[dict],
    nlp_result: dict
) -> dict:
    """
    Main public integration function.

    Person 4 can import this function without changing the interface.
    """

    # Run detection components.
    rule_result = analyze_rules(message)
    url_results = analyze_urls(urls)

    nlp_score, nlp_notes = normalize_nlp_result(nlp_result)
    url_score = calculate_url_score(url_results)

    # No rule findings means there is no positive rule evidence.
    # Do not treat the absence of a finding as negative evidence.
    rule_score = (
        rule_result["score"]
        if rule_result["findings"]
        else None
    )

    components = {
        "nlp_score": nlp_score,
        "rule_score": rule_score,
        "url_score": url_score,
    }

    # Check whether any component produced actual evidence.
    has_rule_evidence = bool(rule_result["findings"])

    has_url_evidence = any(
        item.get("findings") for item in url_results
    )

    inconclusive = (
        nlp_score is None
        and not has_rule_evidence
        and not has_url_evidence
    )

    # Calculate the combined score.
    base_score = calculate_final_score(components)
    corroboration_bonus = calculate_corroboration_bonus(components)

    final_score = min(100, base_score + corroboration_bonus)
    risk_level = get_risk_level(final_score, inconclusive)

    # Collect evidence.
    evidence = []

    for item in rule_result["evidence"]:
        evidence.append({
            "source": "rule_engine",
            "rule": item["rule"],
            "description": item["description"],
            "matched_text": item["matched_text"],
        })

    for url in url_results:
        for item in url["evidence"]:
            evidence.append({
                "source": "url_analyzer",
                "description": item,
                "url": url["url"],
            })

    for note in nlp_notes:
        evidence.append({
            "source": "nlp_classifier",
            "description": note,
        })

    if nlp_score is not None:
        evidence.append({
            "source": "nlp_classifier",
            "description": (
                f"NLP classified the message as "
                f"'{nlp_result['label']}' with "
                f"{float(nlp_result['confidence']) * 100:.1f}% confidence."
            ),
        })

    if corroboration_bonus:
        evidence.append({
            "source": "risk_scorer",
            "description": (
                "Multiple independent detection components reported "
                "strong suspicious signals. A prototype corroboration "
                "bonus was applied."
            ),
        })

    # Determine which components actually contributed.
    available_components = [
        name for name, score in components.items()
        if score is not None
    ]

    available_components = [
        name.replace("_score", "")
        for name in available_components
    ]

    missing_components = [
        name for name in ("nlp", "rules", "urls")
        if name not in available_components
    ]

    # Link verification status is separate from the phishing risk level.
    has_shortened_url = any(
        "url_shortener" in item.get("findings", [])
        for item in url_results
    )

    if has_shortened_url:
        link_status = "UNVERIFIED_SHORTENER"
    elif not urls:
        link_status = "NO_URL_PROVIDED"
    elif has_url_evidence:
        link_status = "REVIEW_RECOMMENDED"
    else:
        link_status = "NO_URL_FLAGS_DETECTED"

    # Recommendations.
    recommendations = []

    if has_rule_evidence:
        recommendations.append(
            "Check unexpected requests for OTPs, passwords, "
            "financial information or urgent actions."
        )

    if has_url_evidence:
        recommendations.append(
            "Verify suspicious destinations using the organization's "
            "official app or a previously known website address."
        )

    if has_shortened_url:
        recommendations.append(
            "The shortened link hides its final destination. "
            "Verify it through a trusted channel before considering it."
        )

    if inconclusive:
        recommendations.append(
            "There is insufficient evidence for a reliable assessment. "
            "Verify the sender and request through a known channel."
        )

    recommendations.extend([
        "Never share OTPs, passwords, PINs or CVVs through unexpected messages.",
        "Do not open suspicious links to investigate them.",
        "Verify important requests through a known official contact channel."
    ])

    recommendations = list(dict.fromkeys(recommendations))

    return {
        "score": final_score,
        "risk_level": risk_level,
        "assessment_status": (
            "INCONCLUSIVE" if inconclusive
            else "PARTIAL" if missing_components
            else "COMPLETE"
        ),
        "components": components,
        "available_components": available_components,
        "missing_components": missing_components,
        "corroboration_bonus": corroboration_bonus,
        "link_status": link_status,
        "evidence": evidence,
        "url_analysis": url_results,
        "rule_findings": rule_result["findings"],
        "recommendations": recommendations,
        "disclaimer": (
            "This prototype risk score is an indicator, not a probability "
            "or guarantee that a message is malicious or safe. Risk "
            "thresholds, weights and heuristics require validation on "
            "representative benign and suspicious messages."
        )
    }
