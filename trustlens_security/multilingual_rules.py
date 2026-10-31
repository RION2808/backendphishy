"""Extra rule patterns for Hindi (Devanagari), Kannada and romanised Hindi.

IMPORTANT: no `\\b` here. Python's \\b treats Indic vowel signs (matras) as
non-word characters, so it fails at the end of most Hindi/Kannada words.
All groups must be non-capturing (?:...) because the rule engine uses
re.findall, which would otherwise return group fragments instead of matches.

These are starting patterns; extend them as you collect real scam messages.
"""

_ZW = "[\u200c\u200d]?"  # optional zero-width joiner/non-joiner (Kannada)

# Verbs meaning "share / tell / send / enter" next to OTP, PIN, password.
_HI_SHARE = r"(?:साझा|शेयर|बताएं|बताएँ|बताइए|बताओ|भेजें|भेजिए|दर्ज|डालें|दें|दीजिए)"
_KN_SHARE = r"(?:ಹಂಚಿ|ಶೇರ್|ಹೇಳಿ|ಕಳುಹಿಸಿ|ನಮೂದಿಸಿ|ನೀಡಿ|ಕೊಡಿ)"
_HI_SECRET = r"(?:ओटीपी|otp|पिन|पासवर्ड|सीवीवी|cvv)"
_KN_SECRET = r"(?:ಒಟಿಪಿ|otp|ಪಿನ್|ಪಾಸ್" + _ZW + r"ವರ್ಡ್|ಸಿವಿವಿ|cvv)"

MULTILINGUAL_PATTERNS = {
    "urgency_pressure": [
        # Hindi
        r"तुरंत",
        r"तत्काल",
        r"जल्द से जल्द",
        r"आज ही",
        r"अभी\s+(?:क्लिक|करें|अपडेट|वेरिफ|भुगतान|कॉल)",
        r"(?:आखिरी|अंतिम)\s+चेतावनी",
        r"\d+\s*(?:घंटे|घण्टे|मिनट|दिन)\s*(?:के\s*)?(?:अंदर|भीतर)",
        r"खाता.{0,30}(?:बंद|ब्लॉक|निलंबित|सस्पेंड|लॉक)",
        r"(?:समाप्त|एक्सपायर)\s*हो\s*(?:जाएगा|जाएगी|ने वाला|ने वाली|रहा)",
        # Kannada
        r"ತಕ್ಷಣ",
        r"ತುರ್ತು",
        r"ಈಗಲೇ",
        r"ಇಂದೇ",
        r"ಕೊನೆಯ ಎಚ್ಚರಿಕೆ",
        r"\d+\s*(?:ಗಂಟೆ|ನಿಮಿಷ|ದಿನ)(?:ಗಳ)?(?:ಒಳಗೆ|ಒಳಗಾಗಿ)",
        r"ಖಾತೆ.{0,30}(?:ನಿರ್ಬಂಧ|ಬ್ಲಾಕ್|ಸ್ಥಗಿತ|ಲಾಕ್|ಮುಚ್ಚ)",
        # Romanised Hindi
        r"\bturant\b",
        r"\bjaldi se jaldi\b",
        r"\baaj hi\b",
        r"\babhi\s+(?:click|karo|karein|update|verify|payment)",
        r"\bkhata.{0,30}(?:band|block|suspend)",
    ],
    "credential_request": [
        # Hindi
        _HI_SECRET + r".{0,25}" + _HI_SHARE,
        _HI_SHARE + r".{0,25}" + _HI_SECRET,
        r"कार्ड\s*(?:की\s*)?(?:जानकारी|विवरण|डिटेल|नंबर)",
        r"लॉगिन\s*(?:विवरण|जानकारी|डिटेल)",
        # Kannada
        _KN_SECRET + r".{0,25}" + _KN_SHARE,
        _KN_SHARE + r".{0,25}" + _KN_SECRET,
        r"ಕಾರ್ಡ್\s*(?:ವಿವರ|ಮಾಹಿತಿ|ಸಂಖ್ಯೆ)",
        r"ಲಾಗಿನ್\s*(?:ವಿವರ|ಮಾಹಿತಿ)",
        # Romanised Hindi
        r"\botp.{0,25}(?:share|batao|bataiye|bhejo|bhejein|dijiye|do)\b",
        r"\b(?:share|batao|bataiye|bhejo|bhejein|dijiye)\b.{0,25}\b(?:otp|pin|password)\b",
    ],
    "financial_request": [
        # Hindi
        r"पैसे?\s*(?:भेजें|भेजिए|ट्रांसफर|जमा|दें)",
        r"भुगतान\s*(?:करें|कीजिए|कीजिये|तुरंत)",
        r"अभी\s*भुगतान",
        r"बैंक\s*(?:विवरण|डिटेल|जानकारी)",
        r"रिफंड\s*(?:प्राप्त|क्लेम|पाने|के लिए)",
        r"शुल्क\s*(?:जमा|का भुगतान|भरें)",
        # Kannada
        r"ಹಣ\s*(?:ಕಳುಹಿಸಿ|ವರ್ಗಾಯಿಸಿ|ಪಾವತಿಸಿ|ಜಮಾ)",
        r"ಪಾವತಿ\s*(?:ಮಾಡಿ|ಮಾಡಿರಿ)",
        r"ಈಗಲೇ\s*ಪಾವತಿ",
        r"ಬ್ಯಾಂಕ್\s*(?:ವಿವರ|ಮಾಹಿತಿ)",
        r"ರಿಫಂಡ್",
        r"ಶುಲ್ಕ\s*(?:ಪಾವತಿ|ಕಟ್ಟಿ|ಜಮಾ)",
        # Romanised Hindi
        r"\bpaise?\s+(?:bhejo|bhejein|transfer|jama)",
        r"\bpayment\s+(?:karo|karein|kijiye)",
    ],
    "delivery_scam": [
        # Hindi
        r"डिलीवरी.{0,25}(?:असफल|विफल|फेल|नहीं हो (?:सकी|पाई|पाया))",
        r"(?:पार्सल|पैकेज).{0,40}(?:रोक|वापस|लौटा|असफल|विफल|अटक)",
        r"(?:री\s*-?\s*डिलीवरी|पुनः\s*डिलीवरी|री\s*-?\s*शेड्यूल)",
        r"(?:सीमा\s*शुल्क|कस्टम(?:्स)?\s*(?:शुल्क|चार्ज))",
        r"पता\s*(?:कन्फर्म|सत्यापित|अपडेट|की पुष्टि)",
        # Kannada
        r"ಡೆಲಿವರಿ.{0,25}(?:ವಿಫಲ|ಆಗಲಿಲ್ಲ|ಸಾಧ್ಯವಾಗಲಿಲ್ಲ|ಸಾಧ್ಯವಾಗಿಲ್ಲ)",
        r"(?:ಪಾರ್ಸೆಲ್|ಪಾರ್ಸಲ್|ಪ್ಯಾಕೇಜ್).{0,40}(?:ಹಿಂತಿರುಗ|ವಾಪಸ್|ವಿಫಲ|ತಡೆ)",
        r"ಕಸ್ಟಮ್ಸ್\s*(?:ಶುಲ್ಕ|ಚಾರ್ಜ್)?",
        r"ವಿಳಾಸ\s*(?:ಖಚಿತ|ದೃಢೀಕರಿ|ಅಪ್" + _ZW + r"ಡೇಟ್)",
        # Romanised Hindi
        r"\b(?:parcel|package|delivery).{0,30}(?:wapas|fail|return|rok)",
    ],
    "account_update_request": [
        # Hindi
        r"(?:केवाईसी|kyc)\s*(?:अपडेट|सत्यापन|वेरिफ|समाप्त|एक्सपायर|पूरा)",
        r"(?:अपना|अपनी|आपका|आपकी)\s*(?:खाता|विवरण|जानकारी|पहचान|केवाईसी|पैन).{0,20}(?:अपडेट|सत्यापित|वेरिफाई|पुष्टि)",
        r"(?:लिंक|यहाँ|यहां)\s*(?:पर\s*)?क्लिक",
        # Kannada
        r"(?:ಕೆವೈಸಿ|kyc)\s*(?:ಅಪ್" + _ZW + r"ಡೇಟ್|ಪರಿಶೀಲ|ದೃಢೀಕರಣ|ಮುಕ್ತಾಯ|ಪೂರ್ಣ)",
        r"(?:ನಿಮ್ಮ)\s*(?:ಖಾತೆ|ವಿವರ|ಮಾಹಿತಿ|ಗುರುತು|ಕೆವೈಸಿ).{0,20}(?:ಅಪ್" + _ZW + r"ಡೇಟ್|ಪರಿಶೀಲ|ದೃಢೀಕರಿಸಿ)",
        r"(?:ಲಿಂಕ್|ಇಲ್ಲಿ)\s*(?:ಮೇಲೆ\s*)?ಕ್ಲಿಕ್",
        # Romanised Hindi
        r"\bkyc\s+(?:update|expire|pending|verify)",
        r"\b(?:link|yahan)\s+(?:par|pe)\s+click",
    ],
    "impersonation_claim": [
        # Hindi
        r"बैंक\s*(?:की\s*)?(?:सुरक्षा\s*टीम|सिक्योरिटी)",
        r"आयकर\s*विभाग",
        r"(?:पुलिस\s*विभाग|साइबर\s*क्राइम|सीबीआई)",
        r"ग्राहक\s*(?:सहायता|सेवा)",
        r"सरकारी\s*अधिकारी",
        r"हम\s*आपके\s*बैंक",
        # Kannada
        r"ಬ್ಯಾಂಕ್\s*(?:ಭದ್ರತಾ\s*ತಂಡ|ಸೆಕ್ಯೂರಿಟಿ)",
        r"ಆದಾಯ\s*ತೆರಿಗೆ\s*ಇಲಾಖೆ",
        r"(?:ಪೊಲೀಸ್\s*ಇಲಾಖೆ|ಸೈಬರ್\s*ಕ್ರೈಂ|ಸಿಬಿಐ)",
        r"ಗ್ರಾಹಕ\s*(?:ಸೇವಾ|ಬೆಂಬಲ)",
        r"ಸರ್ಕಾರಿ\s*ಅಧಿಕಾರಿ",
        # Romanised Hindi
        r"\bbank\s+(?:security|suraksha)\s+team\b",
        r"\bincome\s+tax\s+vibhag\b",
    ],
    "reward_bait": [
        # Hindi
        r"आप(?:ने)?\s*(?:जीत|जीता)",
        r"बधाई.{0,40}(?:इनाम|पुरस्कार|जीत|ईनाम)",
        r"(?:इनाम|पुरस्कार|ईनाम)\s*(?:पाने|क्लेम|प्राप्त)",
        r"मुफ़?्त\s*(?:इनाम|उपहार|गिफ्ट)",
        r"लॉटरी",
        # Kannada
        r"ನೀವು\s*ಗೆದ್ದಿದ್ದೀರಿ",
        r"ಅಭಿನಂದನೆ.{0,40}(?:ಬಹುಮಾನ|ಗೆಲು)",
        r"ಉಚಿತ\s*(?:ಬಹುಮಾನ|ಉಡುಗೊರೆ)",
        r"ಲಾಟರಿ",
        # Romanised Hindi
        r"\baap(?:ne)?\s+(?:jeet|jeeta)\b",
        r"\binaam\s+(?:jeeta|claim)",
    ],
    "threat_or_consequence": [
        # Hindi
        r"कानूनी\s*कार्रवाई",
        r"खाता.{0,25}(?:बंद|ब्लॉक)\s*(?:कर\s*दिया\s*जाएगा|हो\s*जाएगा|होगा)",
        r"जुर्माना",
        r"गिरफ्तार",
        r"(?:पुलिस\s*केस|एफआईआर|एफ\.?आई\.?आर)",
        r"सेवा\s*(?:बंद|समाप्त)\s*(?:कर\s*दी\s*जाएगी|हो\s*जाएगी)",
        # Kannada
        r"ಕಾನೂನು\s*ಕ್ರಮ",
        r"ಖಾತೆ.{0,25}(?:ಮುಚ್ಚ|ನಿರ್ಬಂಧ).{0,15}(?:ಲಾಗುವುದು|ಆಗುತ್ತದೆ|ಆಗುವುದು)",
        r"ದಂಡ",
        r"(?<!ಂ)ಬಂಧ(?:ನ|ಿಸ)",  # not ಸಂಬಂಧ (relationship)
        r"(?:ಪೊಲೀಸ್\s*ಪ್ರಕರಣ|ಎಫ್" + _ZW + r"ಐಆರ್)",
        # Romanised Hindi
        r"\bkhata.{0,25}band\s+ho\s+jayega\b",
        r"\bkanooni\s+karyavahi\b",
    ],
}
