
from .domain_checker import (
    analyze_lookalike_domain,
    find_brand_in_labels,
    find_scam_keywords,
    OFFICIAL_DOMAINS,
)

import ipaddress
import re
from urllib.parse import urlsplit

import tldextract


# Keep analysis offline and predictable.
extract_domain = tldextract.TLDExtract(suffix_list_urls=())


SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "rb.gy", "shorturl.at", "ow.ly", "buff.ly", "rebrand.ly",
}

SUSPICIOUS_SCHEMES = {
    "javascript", "data", "file", "vbscript",
}

# Cheap / abused TLDs. Not proof of anything alone, but common in scam links.
SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "tk", "ml", "ga", "cf", "gq", "click", "link",
    "vip", "buzz", "cyou", "rest", "monster", "work", "support",
}

# Words in the path/query that ask for logins or personal details.
SENSITIVE_PATH_WORDS = {
    "login", "signin", "verify", "verification", "otp", "kyc", "password",
    "confirm", "payment", "secure", "update", "refund", "reschedule",
}


def get_registered_domain(host: str) -> str:
    """Registered domain (e.g. example.co.uk) across tldextract versions."""
    extracted = extract_domain(host)
    return (
        getattr(extracted, "top_domain_under_public_suffix", None)
        or getattr(extracted, "registered_domain", None)
        or host
    )


def normalize_url(raw_url: str) -> str:
    """Normalize a URL without contacting its destination."""

    if not isinstance(raw_url, str):
        raise ValueError("URL must be a string")

    raw_url = raw_url.strip()

    if not raw_url:
        raise ValueError("Empty URL")

    if any(ord(char) < 32 for char in raw_url):
        raise ValueError("URL contains control characters")

    # Reject malformed scheme-like inputs instead of treating them as domains.
    if "://" not in raw_url and re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw_url):
        raise ValueError("Malformed or unsupported URL scheme")

    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    return raw_url


def validate_hostname(host: str) -> str:
    """Validate and normalize a hostname."""

    if not host:
        raise ValueError("Missing hostname")

    host = host.lower().rstrip(".")

    if not host or "%" in host:
        raise ValueError("Invalid hostname")

    if any(char.isspace() for char in host):
        raise ValueError("Hostname contains whitespace")

    # IP addresses are validated separately.
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    # Convert internationalized domains to ASCII for consistent checking.
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid internationalized hostname")

    if len(host) > 253:
        raise ValueError("Hostname is too long")

    labels = host.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        ):
            raise ValueError("Invalid hostname label")

    return host


def analyze_url(raw_url: str, visible_text: str = "") -> dict:
    """
    Analyze URL structure and visible-text mismatch.

    No DNS lookup, HTTP request, redirect following or page opening occurs.
    """

    evidence = []
    findings = []
    score = 0

    try:
        normalized = normalize_url(raw_url)
        parsed = urlsplit(normalized)

        scheme = parsed.scheme.lower()

        if scheme in SUSPICIOUS_SCHEMES:
            return {
                "url": raw_url,
                "score": 80,
                "findings": ["unsupported_or_dangerous_scheme"],
                "evidence": [f"URL uses the unsupported scheme: {scheme}."],
                "domain": None,
                "valid": False,
            }

        if scheme not in {"http", "https"}:
            return {
                "url": raw_url,
                "score": 40,
                "findings": ["unsupported_scheme"],
                "evidence": ["URL does not use HTTP or HTTPS."],
                "domain": None,
                "valid": False,
            }

        if parsed.username is not None or parsed.password is not None:
            score += 25
            findings.append("embedded_credentials")
            evidence.append(
                "URL contains embedded username or password information."
            )

        host = validate_hostname(parsed.hostname)

        # Validate the port. Accessing parsed.port raises ValueError
        # for malformed or out-of-range port numbers.
        port = parsed.port

        if port is not None and port not in {80, 443}:
            score += 5
            findings.append("unusual_port")
            evidence.append(
                f"URL uses a non-standard port ({port}). "
                "This is not necessarily malicious."
            )

        is_ip = False

        try:
            ipaddress.ip_address(host)
            is_ip = True
            registered_domain = host

            score += 30
            findings.append("ip_address_host")
            evidence.append(
                "Destination uses an IP address instead of a domain name."
            )

        except ValueError:
            registered_domain = get_registered_domain(host) or host

        # Only check brand lookalikes for domain names.
        if not is_ip:
            lookalike_result = analyze_lookalike_domain(registered_domain)

            if lookalike_result["suspicious"]:
                score += 30
                findings.append("possible_lookalike_domain")
                evidence.append(
                    f"Domain resembles the known brand "
                    f"'{lookalike_result['matched_brand']}'. "
                    "Verify through the brand's official channel."
                )

        # Brand names / scam keywords stacked inside an unofficial domain,
        # e.g. "fedex-package-redelivery-support.in".
        if not is_ip:
            is_official = any(
                registered_domain == d or host.endswith("." + d)
                for d in OFFICIAL_DOMAINS
            )

            if not is_official:
                suffix_len = len(registered_domain.split(".")) - 1
                host_labels = host.split(".")
                host_labels = host_labels[:-suffix_len] if suffix_len else host_labels
                brand = (
                    None
                    if "possible_lookalike_domain" in findings
                    else find_brand_in_labels(host_labels)
                )

                if brand:
                    score += 35
                    findings.append("brand_in_unofficial_domain")
                    evidence.append(
                        f"The domain name uses the brand '{brand}' but is not "
                        "an official domain of that brand."
                    )

                registered_label = registered_domain.split(".")[0]
                hits = find_scam_keywords(registered_label)

                if len(hits) >= 2 or (brand and hits):
                    # More stacked scam words -> stronger signal.
                    score += {0: 15, 1: 15, 2: 20, 3: 30}.get(len(hits), 35)
                    findings.append("scam_keywords_in_domain")
                    evidence.append(
                        "The domain stacks words often used in scam links "
                        f"({', '.join(hits)})."
                    )

                if registered_label.count("-") >= 3:
                    score += 10
                    findings.append("excessive_hyphens")
                    evidence.append(
                        "The domain name is a long hyphen-chained phrase, "
                        "a common pattern in throwaway scam domains."
                    )

                tld = registered_domain.rsplit(".", 1)[-1]
                if tld in SUSPICIOUS_TLDS:
                    score += 15
                    findings.append("suspicious_tld")
                    evidence.append(
                        f"The '.{tld}' ending is frequently used by "
                        "short-lived scam sites. This is not proof by itself."
                    )

                path_tokens = {
                    t for t in re.split(r"[^a-z0-9]+",
                                        (parsed.path + " " + parsed.query).lower())
                    if t
                }
                if path_tokens & SENSITIVE_PATH_WORDS:
                    score += 10
                    findings.append("sensitive_path")
                    evidence.append(
                        "The link path asks for a login, verification or "
                        "payment step on an unrecognised domain."
                    )

        if host in SHORTENERS:
            score += 20
            findings.append("url_shortener")
            evidence.append(
                "URL uses a shortening service, so its final destination "
                "is not visible from this link alone."
            )

        if "xn--" in host:
            score += 25
            findings.append("punycode_domain")
            evidence.append(
                "Domain contains punycode. Inspect its displayed characters "
                "carefully for possible lookalike-domain abuse."
            )

        if host.count(".") >= 4:
            score += 10
            findings.append("many_subdomains")
            evidence.append(
                "Domain has an unusually large number of subdomain levels."
            )

        if scheme == "http":
            score += 10
            findings.append("no_https")
            evidence.append(
                "Link uses HTTP rather than HTTPS. This alone does not "
                "prove that the site is malicious."
            )

        if len(raw_url) > 150:
            score += 10
            findings.append("long_url")
            evidence.append(
                "URL is unusually long and deserves closer inspection."
            )

        if "@" in parsed.netloc:
            score += 20
            findings.append("at_symbol_authority")
            evidence.append(
                "URL contains an @ symbol in its authority section, "
                "which can make the actual hostname less obvious."
            )

        if visible_text:
            visible_match = re.search(
                r"(?:https?://)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})",
                visible_text.strip(),
                re.IGNORECASE,
            )

            if visible_match:
                visible_host = visible_match.group(1).lower()

                if visible_host != host:
                    score += 30
                    findings.append("visible_destination_mismatch")
                    evidence.append(
                        "The domain shown in the link text differs from "
                        "the actual destination hostname."
                    )

        return {
            "url": raw_url,
            "score": min(score, 100),
            "findings": findings,
            "evidence": evidence,
            "domain": registered_domain,
            "valid": True,
        }

    except (ValueError, UnicodeError):
        return {
            "url": raw_url,
            "score": 20,
            "findings": ["url_parse_error"],
            "evidence": [
                "URL could not be parsed reliably. Treat the destination "
                "as unverified."
            ],
            "domain": None,
            "valid": False,
        }


def analyze_urls(urls: list[dict]) -> list[dict]:
    """Analyze a list of URLs."""

    results = []

    for item in urls:
        if isinstance(item, str):
            raw_url = item
            visible_text = ""

        elif isinstance(item, dict):
            raw_url = item.get("url", "")
            visible_text = item.get("visible_text", "")

        else:
            raw_url = ""
            visible_text = ""

        try:
            results.append(analyze_url(raw_url, visible_text))
        except Exception as exc:  # never let one URL break scoring
            print("URL analysis error:", repr(exc))
            results.append({
                "url": raw_url,
                "score": 20,
                "findings": ["url_parse_error"],
                "evidence": ["URL could not be analysed. Treat it as unverified."],
                "domain": None,
                "valid": False,
            })

    return results
