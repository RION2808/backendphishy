# -*- coding: utf-8 -*-
"""User-facing text in English, Hindi and Kannada.

Gemini produces the long explanation, but everything else the extension shows
(evidence lines, advice, summary, and the whole answer when Gemini is down)
comes from here, so the result is in the user's language either way.

NOTE: the Hindi and Kannada wording was written carefully but should be
reviewed by a native speaker before you ship it.
"""
import re

LANG_NAMES = {"en": "English", "hi": "Hindi", "kn": "Kannada"}

# Used inside the Gemini prompt so the model writes in the right script.
GEMINI_LANGUAGE = {
    "en": "English",
    "hi": "Hindi, written in Devanagari script (हिन्दी)",
    "kn": "Kannada, written in Kannada script (ಕನ್ನಡ)",
}

LEVEL_LABEL = {
    "en": {"HIGH": "high", "MODERATE": "moderate", "LOW": "low", "INCONCLUSIVE": "inconclusive"},
    "hi": {"HIGH": "उच्च", "MODERATE": "मध्यम", "LOW": "कम", "INCONCLUSIVE": "अनिर्णायक"},
    "kn": {"HIGH": "ಹೆಚ್ಚು", "MODERATE": "ಮಧ್ಯಮ", "LOW": "ಕಡಿಮೆ", "INCONCLUSIVE": "ನಿರ್ಣಾಯಕವಲ್ಲ"},
}

# ---------------------------------------------------------------- text rules
RULE_DESC = {
    "hi": {
        "urgency_pressure": "संदेश आपको जल्दबाज़ी में कदम उठाने के लिए दबाव डालता है।",
        "credential_request": "संदेश OTP, पासवर्ड या PIN जैसी संवेदनशील जानकारी माँगता है।",
        "financial_request": "संदेश पैसे भेजने या भुगतान करने के लिए कहता है या दबाव डालता है।",
        "delivery_scam": "संदेश डिलीवरी असफल होने या पार्सल शुल्क का बहाना बनाता है, जो ठगी का आम तरीका है।",
        "account_update_request": "संदेश लिंक के ज़रिए आपकी निजी जानकारी अपडेट या सत्यापित करने को कहता है।",
        "impersonation_claim": "संदेश किसी संस्था या अधिकारी का प्रतिनिधि होने का दावा करता है।",
        "reward_bait": "संदेश इनाम या पुरस्कार का लालच देकर आपसे कार्रवाई करवाना चाहता है।",
        "threat_or_consequence": "संदेश किसी नुकसान या कार्रवाई की धमकी देता है।",
    },
    "kn": {
        "urgency_pressure": "ಸಂದೇಶವು ತಕ್ಷಣ ಕ್ರಮ ಕೈಗೊಳ್ಳುವಂತೆ ಒತ್ತಡ ಹೇರುತ್ತದೆ.",
        "credential_request": "ಸಂದೇಶವು OTP, ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ ಪಿನ್‌ನಂತಹ ಗೌಪ್ಯ ಮಾಹಿತಿಯನ್ನು ಕೇಳುತ್ತದೆ.",
        "financial_request": "ಸಂದೇಶವು ಹಣ ಕಳುಹಿಸಲು ಅಥವಾ ಪಾವತಿ ಮಾಡಲು ಕೇಳುತ್ತದೆ ಅಥವಾ ಒತ್ತಡ ಹೇರುತ್ತದೆ.",
        "delivery_scam": "ಸಂದೇಶವು ವಿಫಲ ಡೆಲಿವರಿ ಅಥವಾ ಪಾರ್ಸೆಲ್ ಶುಲ್ಕದ ನೆಪ ಹೇಳುತ್ತದೆ; ಇದು ವಂಚನೆಯ ಸಾಮಾನ್ಯ ವಿಧಾನ.",
        "account_update_request": "ಸಂದೇಶವು ಲಿಂಕ್ ಮೂಲಕ ನಿಮ್ಮ ವೈಯಕ್ತಿಕ ವಿವರಗಳನ್ನು ಅಪ್‌ಡೇಟ್ ಅಥವಾ ದೃಢೀಕರಿಸಲು ಹೇಳುತ್ತದೆ.",
        "impersonation_claim": "ಸಂದೇಶವು ಯಾವುದೋ ಸಂಸ್ಥೆ ಅಥವಾ ಅಧಿಕಾರಿಯ ಪ್ರತಿನಿಧಿ ಎಂದು ಹೇಳಿಕೊಳ್ಳುತ್ತದೆ.",
        "reward_bait": "ಸಂದೇಶವು ಬಹುಮಾನದ ಆಮಿಷ ತೋರಿಸಿ ನಿಮ್ಮಿಂದ ಕ್ರಮ ಮಾಡಿಸಲು ಯತ್ನಿಸುತ್ತದೆ.",
        "threat_or_consequence": "ಸಂದೇಶವು ಹಾನಿ ಅಥವಾ ಕ್ರಮದ ಬೆದರಿಕೆ ಹಾಕುತ್ತದೆ.",
    },
}

# --------------------------------------------------------------- link checks
# {d} = a detail pulled out of the English evidence (brand name, port, ...).
URL_FINDING = {
    "embedded_credentials": {
        "hi": "लिंक में यूज़रनेम या पासवर्ड जैसी जानकारी जुड़ी हुई है।",
        "kn": "ಲಿಂಕ್‌ನಲ್ಲಿ ಬಳಕೆದಾರ ಹೆಸರು ಅಥವಾ ಪಾಸ್‌ವರ್ಡ್ ಮಾಹಿತಿ ಸೇರಿದೆ.",
    },
    "unusual_port": {
        "hi": "लिंक असामान्य पोर्ट ({d}) का उपयोग करता है। यह हमेशा खतरनाक नहीं होता।",
        "kn": "ಲಿಂಕ್ ಅಸಾಮಾನ್ಯ ಪೋರ್ಟ್ ({d}) ಬಳಸುತ್ತದೆ. ಇದು ಯಾವಾಗಲೂ ಅಪಾಯಕಾರಿ ಎಂದೇನಲ್ಲ.",
    },
    "ip_address_host": {
        "hi": "लिंक डोमेन नाम की जगह IP पते का उपयोग करता है।",
        "kn": "ಲಿಂಕ್ ಡೊಮೇನ್ ಹೆಸರಿನ ಬದಲು IP ವಿಳಾಸ ಬಳಸುತ್ತದೆ.",
    },
    "possible_lookalike_domain": {
        "hi": "डोमेन जाने-माने ब्रांड '{d}' से मिलता-जुलता है। ब्रांड के आधिकारिक माध्यम से पुष्टि करें।",
        "kn": "ಡೊಮೇನ್ ಪ್ರಸಿದ್ಧ ಬ್ರ್ಯಾಂಡ್ '{d}' ಅನ್ನು ಹೋಲುತ್ತದೆ. ಬ್ರ್ಯಾಂಡ್‌ನ ಅಧಿಕೃತ ಮಾರ್ಗದ ಮೂಲಕ ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಿ.",
    },
    "brand_in_unofficial_domain": {
        "hi": "डोमेन नाम में ब्रांड '{d}' का नाम है, लेकिन यह उस ब्रांड का आधिकारिक डोमेन नहीं है।",
        "kn": "ಡೊಮೇನ್ ಹೆಸರಿನಲ್ಲಿ '{d}' ಬ್ರ್ಯಾಂಡ್ ಹೆಸರಿದೆ, ಆದರೆ ಅದು ಆ ಬ್ರ್ಯಾಂಡ್‌ನ ಅಧಿಕೃತ ಡೊಮೇನ್ ಅಲ್ಲ.",
    },
    "scam_keywords_in_domain": {
        "hi": "डोमेन में ठगी वाले लिंक में आम शब्द जुड़े हैं ({d})।",
        "kn": "ಡೊಮೇನ್‌ನಲ್ಲಿ ವಂಚನೆ ಲಿಂಕ್‌ಗಳಲ್ಲಿ ಸಾಮಾನ್ಯವಾದ ಪದಗಳನ್ನು ಜೋಡಿಸಲಾಗಿದೆ ({d}).",
    },
    "excessive_hyphens": {
        "hi": "डोमेन नाम कई हाइफ़न से जुड़े लंबे वाक्यांश जैसा है, जो नकली डोमेन में आम है।",
        "kn": "ಡೊಮೇನ್ ಹೆಸರು ಹಲವು ಹೈಫನ್‌ಗಳಿಂದ ಜೋಡಿಸಿದ ಉದ್ದ ಪದಗುಚ್ಛದಂತಿದೆ; ನಕಲಿ ಡೊಮೇನ್‌ಗಳಲ್ಲಿ ಇದು ಸಾಮಾನ್ಯ.",
    },
    "suspicious_tld": {
        "hi": "'{d}' वाले डोमेन अक्सर अल्पकालिक ठगी साइटों में दिखते हैं। यह अकेले प्रमाण नहीं है।",
        "kn": "'{d}' ಅಂತ್ಯದ ಡೊಮೇನ್‌ಗಳು ಅಲ್ಪಕಾಲದ ವಂಚನೆ ಸೈಟ್‌ಗಳಲ್ಲಿ ಹೆಚ್ಚಾಗಿ ಕಾಣುತ್ತವೆ. ಇದು ಮಾತ್ರ ಪುರಾವೆಯಲ್ಲ.",
    },
    "sensitive_path": {
        "hi": "अनजान डोमेन पर लिंक का पथ लॉगिन, सत्यापन या भुगतान जैसा कदम माँगता है।",
        "kn": "ಅಪರಿಚಿತ ಡೊಮೇನ್‌ನಲ್ಲಿ ಲಿಂಕ್ ಲಾಗಿನ್, ದೃಢೀಕರಣ ಅಥವಾ ಪಾವತಿಯಂತಹ ಹಂತವನ್ನು ಕೇಳುತ್ತದೆ.",
    },
    "url_shortener": {
        "hi": "लिंक शॉर्टनर सेवा का उपयोग करता है, इसलिए असली गंतव्य इस लिंक से दिखाई नहीं देता।",
        "kn": "ಲಿಂಕ್ ಶಾರ್ಟ್‌ನರ್ ಸೇವೆ ಬಳಸುತ್ತದೆ, ಆದ್ದರಿಂದ ನಿಜವಾದ ಗಮ್ಯಸ್ಥಾನ ಈ ಲಿಂಕ್‌ನಿಂದ ಕಾಣುವುದಿಲ್ಲ.",
    },
    "punycode_domain": {
        "hi": "डोमेन में punycode है। नकली डोमेन से बचने के लिए दिखने वाले अक्षर ध्यान से जाँचें।",
        "kn": "ಡೊಮೇನ್‌ನಲ್ಲಿ punycode ಇದೆ. ನಕಲಿ ಡೊಮೇನ್ ತಪ್ಪಿಸಲು ಕಾಣುವ ಅಕ್ಷರಗಳನ್ನು ಜಾಗರೂಕತೆಯಿಂದ ಪರಿಶೀಲಿಸಿ.",
    },
    "many_subdomains": {
        "hi": "डोमेन में असामान्य रूप से कई सबडोमेन स्तर हैं।",
        "kn": "ಡೊಮೇನ್‌ನಲ್ಲಿ ಅಸಾಮಾನ್ಯವಾಗಿ ಹಲವು ಸಬ್‌ಡೊಮೇನ್ ಹಂತಗಳಿವೆ.",
    },
    "no_https": {
        "hi": "लिंक HTTPS की जगह HTTP का उपयोग करता है। यह अकेले साइट के खतरनाक होने का प्रमाण नहीं है।",
        "kn": "ಲಿಂಕ್ HTTPS ಬದಲು HTTP ಬಳಸುತ್ತದೆ. ಇದು ಮಾತ್ರ ಸೈಟ್ ಅಪಾಯಕಾರಿ ಎಂಬುದಕ್ಕೆ ಪುರಾವೆಯಲ್ಲ.",
    },
    "long_url": {
        "hi": "लिंक असामान्य रूप से लंबा है और ध्यान से जाँचने लायक है।",
        "kn": "ಲಿಂಕ್ ಅಸಾಮಾನ್ಯವಾಗಿ ಉದ್ದವಾಗಿದ್ದು ಎಚ್ಚರಿಕೆಯಿಂದ ಪರಿಶೀಲಿಸಬೇಕು.",
    },
    "at_symbol_authority": {
        "hi": "लिंक के पते में @ चिह्न है, जिससे असली होस्ट छिप सकता है।",
        "kn": "ಲಿಂಕ್ ವಿಳಾಸದಲ್ಲಿ @ ಚಿಹ್ನೆ ಇದೆ; ಇದರಿಂದ ನಿಜವಾದ ಹೋಸ್ಟ್ ಮರೆಯಾಗಬಹುದು.",
    },
    "visible_destination_mismatch": {
        "hi": "लिंक के टेक्स्ट में दिखाया डोमेन असली गंतव्य से अलग है।",
        "kn": "ಲಿಂಕ್ ಪಠ್ಯದಲ್ಲಿ ತೋರಿಸಿದ ಡೊಮೇನ್ ನಿಜವಾದ ಗಮ್ಯಸ್ಥಾನಕ್ಕಿಂತ ಭಿನ್ನವಾಗಿದೆ.",
    },
    "unsupported_or_dangerous_scheme": {
        "hi": "लिंक असमर्थित या खतरनाक स्कीम ({d}) का उपयोग करता है।",
        "kn": "ಲಿಂಕ್ ಬೆಂಬಲವಿಲ್ಲದ ಅಥವಾ ಅಪಾಯಕಾರಿ ಸ್ಕೀಮ್ ({d}) ಬಳಸುತ್ತದೆ.",
    },
    "unsupported_scheme": {
        "hi": "लिंक HTTP या HTTPS का उपयोग नहीं करता।",
        "kn": "ಲಿಂಕ್ HTTP ಅಥವಾ HTTPS ಬಳಸುವುದಿಲ್ಲ.",
    },
    "url_parse_error": {
        "hi": "लिंक को भरोसेमंद ढंग से पढ़ा नहीं जा सका। गंतव्य को असत्यापित मानें।",
        "kn": "ಲಿಂಕ್ ಅನ್ನು ವಿಶ್ವಾಸಾರ್ಹವಾಗಿ ಓದಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ. ಗಮ್ಯಸ್ಥಾನವನ್ನು ಪರಿಶೀಲಿಸದ್ದು ಎಂದು ಪರಿಗಣಿಸಿ.",
    },
}

# How to pull the {d} detail out of the English evidence sentence.
_DETAIL_QUOTE = re.compile(r"'([^']+)'")
_DETAIL_PAREN = re.compile(r"\(([^)]+)\)")
_DETAIL_COLON = re.compile(r":\s*([A-Za-z]+)")
_DETAIL_KIND = {
    "possible_lookalike_domain": _DETAIL_QUOTE,
    "brand_in_unofficial_domain": _DETAIL_QUOTE,
    "suspicious_tld": _DETAIL_QUOTE,
    "scam_keywords_in_domain": _DETAIL_PAREN,
    "unusual_port": _DETAIL_PAREN,
    "unsupported_or_dangerous_scheme": _DETAIL_COLON,
}


def localize_rule(rule: str, english: str, lang: str) -> str:
    return RULE_DESC.get(lang, {}).get(rule, english)


def localize_url_finding(code: str, english: str, lang: str) -> str:
    template = URL_FINDING.get(code, {}).get(lang)
    if not template:
        return english
    if "{d}" not in template:
        return template
    pattern = _DETAIL_KIND.get(code)
    match = pattern.search(english) if pattern else None
    return template.replace("{d}", match.group(1) if match else "")


# --------------------------------------------------------------------- advice
TIER_ADVICE = {
    "en": {
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
    },
    "hi": {
        "HIGH": [
            "लिंक पर क्लिक न करें, अटैचमेंट न खोलें और इस संदेश का जवाब न दें।",
            "OTP, पासवर्ड, PIN, कार्ड की जानकारी या अपना पता इसके ज़रिए कभी साझा न करें।",
            "दावे की जाँच खुद करें: कंपनी का आधिकारिक ऐप खोलें या उसकी वेबसाइट का पता खुद टाइप करें।",
            "संदेश हटा दें, और अगर पैसे या जानकारी का नुकसान हुआ हो तो रिपोर्ट करें (भारत में: cybercrime.gov.in या 1930 पर कॉल करें)।",
        ],
        "MODERATE": [
            "संदेश की पुष्टि होने तक लिंक पर क्लिक न करें और जवाब न दें।",
            "कंपनी के आधिकारिक ऐप या खुद टाइप की हुई वेबसाइट से जाँच करें।",
            "इस संदेश के ज़रिए निजी या भुगतान संबंधी जानकारी साझा न करें।",
        ],
        "LOW": [
            "बहुत कम चेतावनी संकेत मिले, इसलिए तुरंत कुछ करने की ज़रूरत नहीं है।",
            "अगर आप यह संदेश उम्मीद नहीं कर रहे थे, तो कुछ करने से पहले आधिकारिक ऐप या वेबसाइट से भेजने वाले की जाँच करें।",
        ],
        "INCONCLUSIVE": [
            "किसी भी नतीजे पर पहुँचने के लिए इस संदेश में पर्याप्त जानकारी नहीं है।",
            "अगर यह पैसे या जानकारी माँगता है, तो किसी ऐसे माध्यम से भेजने वाले की पुष्टि करें जिस पर आप पहले से भरोसा करते हैं।",
        ],
    },
    "kn": {
        "HIGH": [
            "ಲಿಂಕ್ ಮೇಲೆ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ, ಅಟ್ಯಾಚ್‌ಮೆಂಟ್ ತೆರೆಯಬೇಡಿ ಮತ್ತು ಈ ಸಂದೇಶಕ್ಕೆ ಉತ್ತರಿಸಬೇಡಿ.",
            "OTP, ಪಾಸ್‌ವರ್ಡ್, ಪಿನ್, ಕಾರ್ಡ್ ವಿವರ ಅಥವಾ ನಿಮ್ಮ ವಿಳಾಸವನ್ನು ಇದರ ಮೂಲಕ ಎಂದಿಗೂ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.",
            "ಹೇಳಿಕೆಯನ್ನು ನೀವೇ ಪರಿಶೀಲಿಸಿ: ಕಂಪನಿಯ ಅಧಿಕೃತ ಆ್ಯಪ್ ತೆರೆಯಿರಿ ಅಥವಾ ಅದರ ವೆಬ್‌ಸೈಟ್ ವಿಳಾಸವನ್ನು ನೀವೇ ಟೈಪ್ ಮಾಡಿ.",
            "ಸಂದೇಶವನ್ನು ಅಳಿಸಿ, ಮತ್ತು ಹಣ ಅಥವಾ ಮಾಹಿತಿ ನಷ್ಟವಾಗಿದ್ದರೆ ವರದಿ ಮಾಡಿ (ಭಾರತದಲ್ಲಿ: cybercrime.gov.in ಅಥವಾ 1930 ಗೆ ಕರೆ ಮಾಡಿ).",
        ],
        "MODERATE": [
            "ಸಂದೇಶದ ಬಗ್ಗೆ ಖಚಿತಪಡಿಸಿಕೊಳ್ಳುವವರೆಗೆ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ ಅಥವಾ ಉತ್ತರಿಸಬೇಡಿ.",
            "ಕಂಪನಿಯ ಅಧಿಕೃತ ಆ್ಯಪ್ ಅಥವಾ ನೀವೇ ಟೈಪ್ ಮಾಡಿದ ವೆಬ್‌ಸೈಟ್ ಮೂಲಕ ಪರಿಶೀಲಿಸಿ.",
            "ಈ ಸಂದೇಶದ ಮೂಲಕ ವೈಯಕ್ತಿಕ ಅಥವಾ ಪಾವತಿ ಮಾಹಿತಿಯನ್ನು ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.",
        ],
        "LOW": [
            "ಕಡಿಮೆ ಎಚ್ಚರಿಕೆ ಚಿಹ್ನೆಗಳು ಕಂಡುಬಂದಿವೆ, ಆದ್ದರಿಂದ ತುರ್ತು ಕ್ರಮ ಅಗತ್ಯವಿಲ್ಲ.",
            "ನೀವು ಈ ಸಂದೇಶವನ್ನು ನಿರೀಕ್ಷಿಸಿರದಿದ್ದರೆ, ಕ್ರಮ ಕೈಗೊಳ್ಳುವ ಮೊದಲು ಅಧಿಕೃತ ಆ್ಯಪ್ ಅಥವಾ ವೆಬ್‌ಸೈಟ್ ಮೂಲಕ ಕಳುಹಿಸಿದವರನ್ನು ಪರಿಶೀಲಿಸಿ.",
        ],
        "INCONCLUSIVE": [
            "ಯಾವುದೇ ತೀರ್ಮಾನಕ್ಕೆ ಬರಲು ಈ ಸಂದೇಶದಲ್ಲಿ ಸಾಕಷ್ಟು ಮಾಹಿತಿ ಇಲ್ಲ.",
            "ಇದು ಹಣ ಅಥವಾ ಮಾಹಿತಿ ಕೇಳುತ್ತಿದ್ದರೆ, ನೀವು ಈಗಾಗಲೇ ನಂಬುವ ಮಾರ್ಗದ ಮೂಲಕ ಕಳುಹಿಸಿದವರನ್ನು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಿ.",
        ],
    },
}

SUMMARY = {
    "en": {
        "HIGH": "This message shows several strong signs of a scam. Don't click the link or reply.",
        "MODERATE": "This message has some warning signs. Verify it through an official channel before acting.",
        "LOW": "Few warning signs were found, but stay careful with unexpected requests.",
        "INCONCLUSIVE": "There isn't enough evidence for a reliable result. Verify the sender through an official channel.",
    },
    "hi": {
        "HIGH": "इस संदेश में ठगी के कई मज़बूत संकेत हैं। लिंक पर क्लिक न करें और जवाब न दें।",
        "MODERATE": "इस संदेश में कुछ चेतावनी संकेत हैं। कोई कदम उठाने से पहले आधिकारिक माध्यम से इसकी पुष्टि करें।",
        "LOW": "बहुत कम चेतावनी संकेत मिले, फिर भी अनजान अनुरोधों से सावधान रहें।",
        "INCONCLUSIVE": "विश्वसनीय नतीजे के लिए पर्याप्त प्रमाण नहीं है। आधिकारिक माध्यम से भेजने वाले की पुष्टि करें।",
    },
    "kn": {
        "HIGH": "ಈ ಸಂದೇಶದಲ್ಲಿ ವಂಚನೆಯ ಹಲವು ಬಲವಾದ ಸೂಚನೆಗಳಿವೆ. ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ ಮತ್ತು ಉತ್ತರಿಸಬೇಡಿ.",
        "MODERATE": "ಈ ಸಂದೇಶದಲ್ಲಿ ಕೆಲವು ಎಚ್ಚರಿಕೆ ಸೂಚನೆಗಳಿವೆ. ಕ್ರಮ ಕೈಗೊಳ್ಳುವ ಮೊದಲು ಅಧಿಕೃತ ಮಾರ್ಗದ ಮೂಲಕ ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಿ.",
        "LOW": "ಕಡಿಮೆ ಎಚ್ಚರಿಕೆ ಸೂಚನೆಗಳು ಕಂಡುಬಂದಿವೆ, ಆದರೂ ಅಪರಿಚಿತ ವಿನಂತಿಗಳ ಬಗ್ಗೆ ಜಾಗರೂಕರಾಗಿರಿ.",
        "INCONCLUSIVE": "ವಿಶ್ವಾಸಾರ್ಹ ಫಲಿತಾಂಶಕ್ಕೆ ಸಾಕಷ್ಟು ಪುರಾವೆ ಇಲ್ಲ. ಅಧಿಕೃತ ಮಾರ್ಗದ ಮೂಲಕ ಕಳುಹಿಸಿದವರನ್ನು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಿ.",
    },
}

# Detector advice (risk_scorer.py) keyed by its English text.
DETECTOR_ADVICE = {
    "Check unexpected requests for OTPs, passwords, financial information or urgent actions.": {
        "hi": "OTP, पासवर्ड, वित्तीय जानकारी या तुरंत कदम उठाने के अनचाहे अनुरोधों की जाँच करें।",
        "kn": "OTP, ಪಾಸ್‌ವರ್ಡ್, ಹಣಕಾಸು ಮಾಹಿತಿ ಅಥವಾ ತುರ್ತು ಕ್ರಮದ ಅನಿರೀಕ್ಷಿತ ವಿನಂತಿಗಳನ್ನು ಪರಿಶೀಲಿಸಿ.",
    },
    "Verify suspicious destinations using the organization's official app or a previously known website address.": {
        "hi": "संदिग्ध गंतव्य को संस्था के आधिकारिक ऐप या पहले से ज्ञात वेबसाइट पते से सत्यापित करें।",
        "kn": "ಸಂಶಯಾಸ್ಪದ ಗಮ್ಯಸ್ಥಾನವನ್ನು ಸಂಸ್ಥೆಯ ಅಧಿಕೃತ ಆ್ಯಪ್ ಅಥವಾ ಮೊದಲೇ ತಿಳಿದಿರುವ ವೆಬ್‌ಸೈಟ್ ವಿಳಾಸದ ಮೂಲಕ ಪರಿಶೀಲಿಸಿ.",
    },
    "The shortened link hides its final destination. Verify it through a trusted channel before considering it.": {
        "hi": "छोटा किया गया लिंक अपना असली गंतव्य छिपाता है। इसे खोलने से पहले किसी भरोसेमंद माध्यम से जाँच लें।",
        "kn": "ಚಿಕ್ಕದಾಗಿಸಿದ ಲಿಂಕ್ ಅಂತಿಮ ಗಮ್ಯಸ್ಥಾನವನ್ನು ಮರೆಮಾಡುತ್ತದೆ. ಅದನ್ನು ಪರಿಗಣಿಸುವ ಮೊದಲು ವಿಶ್ವಾಸಾರ್ಹ ಮಾರ್ಗದ ಮೂಲಕ ಪರಿಶೀಲಿಸಿ.",
    },
    "There is insufficient evidence for a reliable assessment. Verify the sender and request through a known channel.": {
        "hi": "विश्वसनीय आकलन के लिए पर्याप्त प्रमाण नहीं है। भेजने वाले और अनुरोध की पुष्टि किसी जाने-पहचाने माध्यम से करें।",
        "kn": "ವಿಶ್ವಾಸಾರ್ಹ ಮೌಲ್ಯಮಾಪನಕ್ಕೆ ಸಾಕಷ್ಟು ಪುರಾವೆ ಇಲ್ಲ. ಕಳುಹಿಸಿದವರು ಮತ್ತು ವಿನಂತಿಯನ್ನು ತಿಳಿದ ಮಾರ್ಗದ ಮೂಲಕ ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಿ.",
    },
}


def localize_detector_advice(text: str, lang: str):
    """Translated advice, or None when no translation exists for this language."""
    if lang == "en":
        return text
    return DETECTOR_ADVICE.get(text, {}).get(lang)


# ------------------------------------------------------- Gemini-less fallback
FALLBACK = {
    "en": {
        "explanation": "AI explanation unavailable. See the detected signals for details.",
        "safe_recommendations": [
            "Do not click any links in this message.",
            "Do not reply or share personal details.",
        ],
        "verification_steps": [
            "Open the official app or website yourself.",
            "Call the number printed on your card or on the official website.",
        ],
        "uncertainty": "Explanation generated without AI.",
        "summary": "Risk level: {level}.",
    },
    "hi": {
        "explanation": "AI स्पष्टीकरण उपलब्ध नहीं है। विवरण के लिए पाए गए संकेत देखें।",
        "safe_recommendations": [
            "इस संदेश के किसी भी लिंक पर क्लिक न करें।",
            "जवाब न दें और निजी जानकारी साझा न करें।",
        ],
        "verification_steps": [
            "आधिकारिक ऐप या वेबसाइट खुद खोलें।",
            "अपने कार्ड पर या आधिकारिक वेबसाइट पर छपे नंबर पर कॉल करें।",
        ],
        "uncertainty": "यह स्पष्टीकरण AI के बिना तैयार किया गया है।",
        "summary": "जोखिम स्तर: {level}।",
    },
    "kn": {
        "explanation": "AI ವಿವರಣೆ ಲಭ್ಯವಿಲ್ಲ. ವಿವರಗಳಿಗಾಗಿ ಪತ್ತೆಯಾದ ಸೂಚನೆಗಳನ್ನು ನೋಡಿ.",
        "safe_recommendations": [
            "ಈ ಸಂದೇಶದ ಯಾವುದೇ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ.",
            "ಉತ್ತರಿಸಬೇಡಿ ಮತ್ತು ವೈಯಕ್ತಿಕ ಮಾಹಿತಿ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.",
        ],
        "verification_steps": [
            "ಅಧಿಕೃತ ಆ್ಯಪ್ ಅಥವಾ ವೆಬ್‌ಸೈಟ್ ಅನ್ನು ನೀವೇ ತೆರೆಯಿರಿ.",
            "ನಿಮ್ಮ ಕಾರ್ಡ್‌ನಲ್ಲಿ ಅಥವಾ ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್‌ನಲ್ಲಿ ಮುದ್ರಿಸಿದ ಸಂಖ್ಯೆಗೆ ಕರೆ ಮಾಡಿ.",
        ],
        "uncertainty": "ಈ ವಿವರಣೆಯನ್ನು AI ಇಲ್ಲದೆ ರಚಿಸಲಾಗಿದೆ.",
        "summary": "ಅಪಾಯದ ಮಟ್ಟ: {level}.",
    },
}


def fallback_explanation(level: str, lang: str) -> dict:
    lang = lang if lang in FALLBACK else "en"
    data = FALLBACK[lang]
    label = LEVEL_LABEL[lang].get(str(level).upper(), str(level))
    return {
        "short_summary": data["summary"].format(level=label),
        "explanation": data["explanation"],
        "safe_recommendations": list(data["safe_recommendations"]),
        "verification_steps": list(data["verification_steps"]),
        "uncertainty": data["uncertainty"],
        "ai_generated": False,
    }
