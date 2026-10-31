import re
import unicodedata

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE = re.compile(r"(?<!\d)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\d)")
LONGNUM = re.compile(r"(?<!\d)\d{9,18}(?!\d)")

# Hindi (०-९) and Kannada (೦-೯) digits -> ASCII, so phone and card numbers
# written in those digits are redacted too.
_INDIC_DIGITS = {ord(c): str(i) for i, c in enumerate("०१२३४५६७८९")}
_INDIC_DIGITS.update({ord(c): str(i) for i, c in enumerate("೦೧೨೩೪೫೬೭೮೯")})


def redact(text: str) -> str:
    text = unicodedata.normalize("NFC", text or "").translate(_INDIC_DIGITS)
    text = EMAIL.sub("[EMAIL]", text)
    text = PHONE.sub("[PHONE]", text)
    text = LONGNUM.sub("[NUMBER]", text)
    return text
