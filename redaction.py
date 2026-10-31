import re

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE = re.compile(r"(?<!\d)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\d)")
LONGNUM = re.compile(r"(?<!\d)\d{9,18}(?!\d)")

def redact(text: str) -> str:
    text = EMAIL.sub("[EMAIL]", text)
    text = PHONE.sub("[PHONE]", text)
    text = LONGNUM.sub("[NUMBER]", text)
    return text