
from difflib import SequenceMatcher
import re


# Small prototype reference list (brand -> official registered domains).
# This should eventually be replaced with maintained brand-domain data.
BRAND_DOMAINS = {
    # Global brands
    "google": ("google.com", "google.co.in", "goo.gl"),
    "paypal": ("paypal.com",),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk"),
    "microsoft": ("microsoft.com", "live.com", "office.com"),
    "apple": ("apple.com", "icloud.com"),
    "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",),
    "netflix": ("netflix.com",),
    "whatsapp": ("whatsapp.com", "whatsapp.net"),
    # Couriers / delivery
    "fedex": ("fedex.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "ups": ("ups.com",),
    "bluedart": ("bluedart.com",),
    "delhivery": ("delhivery.com",),
    "indiapost": ("indiapost.gov.in",),
    # Indian banks, payments, government
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"),
    "hdfc": ("hdfcbank.com",),
    "hdfcbank": ("hdfcbank.com",),
    "icici": ("icicibank.com",),
    "icicibank": ("icicibank.com",),
    "axisbank": ("axisbank.com",),
    "kotak": ("kotak.com",),
    "paytm": ("paytm.com",),
    "phonepe": ("phonepe.com",),
    "flipkart": ("flipkart.com",),
    "irctc": ("irctc.co.in",),
    "incometax": ("incometax.gov.in", "incometaxindia.gov.in"),
    "npci": ("npci.org.in",),
    "uidai": ("uidai.gov.in",),
}

# Kept for backward compatibility: brand -> primary domain.
TRUSTED_DOMAINS = {brand: domains[0] for brand, domains in BRAND_DOMAINS.items()}

# Words that scam domains commonly stack together.
SCAM_KEYWORDS = {
    "support", "help", "verify", "verification", "update", "secure", "security",
    "login", "signin", "account", "refund", "kyc", "redelivery", "reschedule",
    "delivery", "package", "parcel", "tracking", "track", "customs", "billing",
    "payment", "portal", "service", "services", "confirm", "reward", "claim",
}


# Common character substitutions used in lookalike domains.
CHARACTER_SUBSTITUTIONS = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "8": "b",
})


OFFICIAL_DOMAINS = tuple(d for ds in BRAND_DOMAINS.values() for d in ds)


def normalize_domain_for_comparison(domain: str) -> str:
    """Normalize a domain for consistent comparison."""

    if not isinstance(domain, str):
        return ""

    domain = domain.lower().strip().rstrip(".")

    if domain.startswith("www."):
        domain = domain[4:]

    # Convert internationalized domains into ASCII representation.
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return ""

    return domain


def get_registered_label(domain: str) -> str:
    """Extract the main label from a registered domain."""

    parts = domain.split(".")

    if len(parts) < 2:
        return parts[0]

    return parts[-2]


def normalize_lookalike_label(label: str) -> str:
    """Normalize common character substitutions."""

    label = label.translate(CHARACTER_SUBSTITUTIONS)

    # A common homoglyph pattern: rn can resemble m.
    label = label.replace("rn", "m")

    # Remove hyphens for comparison.
    label = label.replace("-", "")

    return label


def find_brand_in_labels(labels: list) -> str | None:
    """
    Detect a brand name used as a word inside a non-official domain,
    e.g. "fedex-package-redelivery-support" or "sbi.secure-login.in".
    """
    for label in labels:
        raw_tokens = [t for t in re.split(r"[-_]+", label) if t]
        # Also check each word with look-alike digits swapped back
        # ("paypa1" -> "paypal", "g00gle" -> "google").
        tokens = list(dict.fromkeys(
            raw_tokens + [t.translate(CHARACTER_SUBSTITUTIONS) for t in raw_tokens]
        ))
        for brand in BRAND_DOMAINS:
            if brand in tokens:
                return brand
            # Brand glued to other text ("paypalsupport"), only for
            # reasonably long brand names to avoid false positives.
            if len(brand) >= 5 and (
                any(t.startswith(brand) or t.endswith(brand) for t in tokens)
            ):
                return brand
    return None


def find_scam_keywords(label: str) -> list:
    tokens = {t for t in re.split(r"[-_]+", label) if t}
    return sorted(tokens & SCAM_KEYWORDS)


def analyze_lookalike_domain(domain: str) -> dict:
    """
    Compare a domain against known brand domains.

    This detects possible lookalikes, not confirmed impersonation.
    """

    domain = normalize_domain_for_comparison(domain)

    if not domain:
        return {
            "suspicious": False,
            "matched_brand": None,
            "similarity": 0.0,
            "brand_in_domain": None,
            "keyword_hits": [],
        }

    # Exact trusted domains and their subdomains should not
    # be classified as lookalikes.
    for trusted_domain in OFFICIAL_DOMAINS:
        if domain == trusted_domain or domain.endswith("." + trusted_domain):
            return {
                "suspicious": False,
                "matched_brand": None,
                "similarity": 1.0,
                "brand_in_domain": None,
                "keyword_hits": [],
            }

    # Only compare the registered-domain label.
    domain_label = get_registered_label(domain)

    if not domain_label or not re.fullmatch(r"[a-z0-9-]+", domain_label):
        return {
            "suspicious": False,
            "matched_brand": None,
            "similarity": 0.0,
            "brand_in_domain": None,
            "keyword_hits": [],
        }

    comparison_label = normalize_lookalike_label(domain_label)

    best_match = None
    best_similarity = 0.0

    for brand, trusted_domain in TRUSTED_DOMAINS.items():

        trusted_label = get_registered_label(trusted_domain)

        similarity = SequenceMatcher(
            None,
            comparison_label,
            trusted_label
        ).ratio()

        if similarity > best_similarity:
            best_similarity = similarity
            best_match = brand

    # Avoid flagging short or unrelated domains.
    suspicious = (
    best_similarity >= 0.80
    and len(comparison_label) >= 5
    )

    # Brand used as a word in an unofficial domain (any label of the host).
    all_labels = [l for l in domain.split(".")[:-1] if re.fullmatch(r"[a-z0-9-]+", l)]
    brand_in_domain = None if suspicious else find_brand_in_labels(all_labels)

    return {
        "suspicious": suspicious,
        "matched_brand": best_match if suspicious else None,
        "similarity": round(best_similarity, 2),
        "brand_in_domain": brand_in_domain,
        "keyword_hits": find_scam_keywords(domain_label),
    }
