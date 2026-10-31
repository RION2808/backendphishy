"""Language helpers: detect English / Hindi / Kannada and normalise text."""
import re
import unicodedata

SUPPORTED = ("en", "hi", "kn")

_DEVANAGARI = re.compile(r"[\u0900-\u097F]")
_KANNADA = re.compile(r"[\u0C80-\u0CFF]")
_LETTER = re.compile(r"[^\W\d_]", re.UNICODE)

# Indic digits -> ASCII, so patterns like "24 घंटे" match "२४ घंटे" too.
_DIGITS = {ord(c): str(i) for i, c in enumerate("०१२३४५६७८९")}
_DIGITS.update({ord(c): str(i) for i, c in enumerate("೦೧೨೩೪೫೬೭೮೯")})

# Romanised Hindi ("Hinglish") marker words. Needs 2+ distinct hits, so a
# stray word in an English message does not flip the language.
_HINGLISH = {
    "aap", "aapka", "aapki", "aapke", "apka", "apki", "turant", "jaldi",
    "kripya", "karein", "kijiye", "kijiye", "bhejein", "bhejo", "batao",
    "bataiye", "khata", "paise", "paisa", "band", "nahi", "hai", "hain",
    "abhi", "jama", "wapas", "dhanyavad", "grahak", "sahayata",
}


def normalize_text(text: str) -> str:
    """NFC-normalise, convert Indic digits, drop zero-width spaces."""
    text = unicodedata.normalize("NFC", text or "")
    text = text.replace("\u200b", "").replace("\ufeff", "")
    return text.translate(_DIGITS)


def detect_language(text: str) -> str:
    """Return 'hi', 'kn' or 'en' based on the script the message is written in."""
    text = text or ""
    letters = len(_LETTER.findall(text))
    if letters == 0:
        return "en"

    hi = len(_DEVANAGARI.findall(text))
    kn = len(_KANNADA.findall(text))

    if max(hi, kn) >= 3 and max(hi, kn) / letters >= 0.2:
        return "kn" if kn > hi else "hi"

    words = set(re.findall(r"[a-z]+", text.lower()))
    if len(words & _HINGLISH) >= 3:
        return "hi"
    return "en"


def resolve_language(requested: str, message: str) -> str:
    """Pick the language of the answer.

    * "hi" / "kn"  -> always honoured (explicit choice in the extension).
    * "auto", empty or unknown -> follow the language of the message.
    * "en" -> English, unless the message itself is clearly Hindi/Kannada
      (so an extension that always sends "en" still answers in the user's
      language).
    """
    requested = (requested or "auto").strip().lower()
    if requested in ("hi", "kn"):
        return requested
    detected = detect_language(message)
    if requested == "en":
        return detected if detected in ("hi", "kn") else "en"
    return detected
