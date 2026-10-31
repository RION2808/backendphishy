import re


RULES = {
    "urgency_pressure": {
        "weight": 15,
        "patterns": [
            r"\bact immediately\b",
            r"\bact now\b",
            r"\bimmediately\b",
            r"\burgent\b",
            r"\blast warning\b",
            r"\bwithin\s+\d+\s+hours?\b",
            r"\bexpires today\b",
            r"\baccount.{0,40}(?:blocked|suspended|locked)\b",
            r"\bwithin\s+\d+\s+(?:minutes?|days?)\b",
            r"\bexpires?\s+(?:soon|in\s+\d+)\b",
        ],
        "description": "Message creates pressure to act quickly."
    },

    "credential_request": {
        "weight": 30,
        "patterns": [
            r"\bshare.{0,20}(?:otp|password|pin)\b",
            r"\bprovide.{0,20}(?:otp|password|pin)\b",
            r"\benter your otp\b",
            r"\bverify your password\b",
            r"\bconfirm your cvv\b",
            r"\bcard details\b",
            r"\blogin credentials\b",
        ],
        "description": "Message requests sensitive authentication information."
    },

    "financial_request": {
        "weight": 20,       
        "patterns": [
            r"\btransfer money\b",
            r"\bsend money\b",
            r"\bmake a payment\b",
            r"\bpay immediately\b",
            r"\bpay now\b",
            r"\bcomplete the payment\b",
            r"\bsubmit payment\b",
            r"\bprovide your bank details\b",
            r"\bshare your bank details\b",
            r"\bclaim your refund\b",
        ],

        "description": "Message requests or pressures a financial action."
    },

    "delivery_scam": {
        "weight": 25,
        "patterns": [
            r"\breschedule your delivery\b",
            r"\bredelivery\b",
            r"\bconfirm your (?:correct )?(?:home )?address\b",
            r"\bunclaimed (?:package|parcel)s?\b",
            r"\b(?:package|parcel)s? will be returned\b",
            r"\bpackage (?:could not|couldn't|cannot) be delivered\b",
            r"\bdelivery (?:attempt )?failed\b",
            r"\b(?:import|customs|clearance|redelivery|handling) (?:fees?|duty|duties|charges?)\b",
        ],
        "description": "Message uses a failed-delivery or parcel-fee pretext, a common scam pattern."
    },

    "account_update_request": {
        "weight": 15,
        "patterns": [
            r"\bupdate your (?:information|details|address|account|kyc)\b",
            r"\bverify your (?:identity|account|details)\b",
            r"\bself-service portal\b",
            r"\bkyc (?:update|verification|expired|pending)\b",
            r"\bclick (?:the )?(?:link|here)\b",
        ],
        "description": "Message asks you to update or verify personal details through a link."
    },

    "impersonation_claim": {
        "weight": 15,
        "patterns": [
            r"\bwe are from your bank\b",
            r"\bbank security team\b",
            r"\bcustomer support team\b",
            r"\bincome tax department\b",
            r"\bgovernment official\b",
            r"\bpolice department\b",
            r"\byour account verification team\b",
        ],
        "description": "Message claims to represent an organization or authority."
    },

    "reward_bait": {
        "weight": 10,
        "patterns": [
            r"\byou have won\b",
            r"\bclaim your prize\b",
            r"\bfree reward\b",
            r"\bexclusive reward\b",
            r"\bcongratulations.{0,40}(?:winner|prize|reward)\b",
        ],
        "description": "Message uses a prize or reward to encourage action."
    },

    "threat_or_consequence": {
        "weight": 15,
        "patterns": [
            r"\blegal action\b",
            r"\byour account will be closed\b",
            r"\byour service will be terminated\b",
            r"\bpolice case\b",
            r"\byou will be fined\b",
            r"\baccount access will be removed\b",
        ],
        "description": "Message threatens a negative consequence."
    },
}


def analyze_rules(message: str) -> dict:
    """
    Identify configured social-engineering signals.

    This is a rule-based signal detector, not a final phishing verdict.
    """

    message = message or ""

    findings = []
    evidence = []
    score = 0

    for rule_name, rule in RULES.items():
        matched = []

        for pattern in rule["patterns"]:
            matches = re.findall(
                pattern,
                message,
                flags=re.IGNORECASE
            )

            if matches:
                matched.extend(matches)

        if matched:
            matched = list(dict.fromkeys(matched))

            score += rule["weight"]

            findings.append(rule_name)

            evidence.append({
                "rule": rule_name,
                "description": rule["description"],
                "matched_text": matched[:4],
                "weight": rule["weight"],
            })

    return {
        "score": min(score, 100),
        "findings": findings,
        "evidence": evidence,
    }
