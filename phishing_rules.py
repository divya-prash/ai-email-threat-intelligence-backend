"""
Phishing Detection Engine using rules, regex, and suspicious keywords.
"""

import re

# Rule-based phishing detection

PHISHING_KEYWORDS = {
    "verify account": 0.9,
    "confirm identity": 0.9,
    "update payment": 0.85,
    "suspend": 0.8,
    "lock": 0.8,
    "click to confirm": 0.85,
    "re-enter password": 0.95,
    "authenticate": 0.7,
    "urgent action": 0.7,
    "act immediately": 0.7,
    "unusual activity": 0.8,
    "security alert": 0.8,
    "confirm details": 0.8,
    "reactivate": 0.8,
    "paypal": 0.6,
    "amazon": 0.5,
    "apple": 0.5,
    "microsoft": 0.5,
    "bank": 0.6,
}

# Expanded production keyword list (phrases commonly used in phishing)
PHISHING_KEYWORDS.update({
    "reset your password": 0.95,
    "reset password": 0.95,
    "password will expire": 0.9,
    "password expiry": 0.9,
    "account suspended": 0.9,
    "verify your identity": 0.9,
    "secure your account": 0.85,
    "billing problem": 0.8,
    "payment failed": 0.8,
    "unauthorized login": 0.85,
    "confirm your account": 0.85,
    "security verification": 0.85,
    "credential": 0.8,
    "authentication failed": 0.8,
    "account locked": 0.9,
    "reactivate account": 0.85,
    "confirm payment": 0.8,
    "update billing": 0.8,
    "verify payment": 0.8,
    "verify email": 0.8,
    "confirm email": 0.8,
    "important notice": 0.6,
    "action required": 0.7,
    "verify now": 0.85,
    "security update": 0.75,
    "account update": 0.7,
    "reset link": 0.9,
})


# goo.gl/secure-login
# login.amaz0n.com
# https://bit.ly/3xYz123
URL_PATTERNS = {
    # Suspicious shortened URLs and common suspicious patterns (also catch hyphenated and obfuscated domains)
    "shortened_url": r"(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|short\.link)",
    "suspicious_domain": r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*(paypa1|amaz0n|mic1osoft|secure-bank-login|mail-security-update|billing-update-portal|secure-kyc-update-bank|delivery-reschedule-now|card-verification-secure|income-tax-ref|upi-payment-alert|google-account-security-alert|global-lottery-claim)\.(?:com|net|in|org|info)",
}

# Additional URL/domain heuristics: tokens often used in phishing domains
SUSPICIOUS_DOMAIN_TOKENS = ["reset", "secure", "security", "update", "login", "account", "verify"]

URL_EXTRACTOR = re.compile(r"https?://[\w\-\./?=#%&]+", re.IGNORECASE)

IP_ADDRESS_PATTERN = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"


def detect_phishing(subject: str, sender: str, body: str) -> float:
    """
    Detect phishing using rule-based approach with regex and keywords.
    
    Args:
        subject: Email subject
        sender: Sender email address
        body: Email body
        
    Returns:
        Phishing score (0.0 - 1.0)
    """
    combined_text = (subject + " " + body).lower()
    phishing_score = 0.0

    # 1. Check for phishing keywords (stronger contribution)
    keyword_score = 0.0
    for keyword, score in PHISHING_KEYWORDS.items():
        if keyword in combined_text:
            keyword_score += score

    # Normalize keyword score but allow higher contribution now (up to 0.6)
    phishing_score += min(keyword_score / max(len(PHISHING_KEYWORDS), 1), 0.6)
    
    # 2. Check for suspicious URLs (shortened URLs, typosquatting)
    url_detected = False
    for pattern_name, pattern in URL_PATTERNS.items():
        if re.search(pattern, combined_text):
            phishing_score += 0.35
            url_detected = True

    # 2b. Extract URLs and look for suspicious domain tokens
    urls = URL_EXTRACTOR.findall(body + " " + subject)
    for url in urls:
        try:
            host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].lower()
            # boost when suspicious tokens present or domain looks obfuscated/typosquatted
            if any(token in host for token in SUSPICIOUS_DOMAIN_TOKENS) or re.search(r"[-0-9]{2,}|secure|update|verify|login|reset", host):
                phishing_score += 0.45
                url_detected = True
        except Exception:
            continue

    # If any external URL is present, treat as strong indicator (catch-all boost)
    if len(urls) > 0:
        phishing_score = min(phishing_score + 0.6, 1.0)
    
    # 3. Check for IP addresses in email body (suspicious)
    if re.search(IP_ADDRESS_PATTERN, body):
        phishing_score += 0.2
    
    # 4. Check sender domain reputation
    phishing_score += _check_sender_reputation(sender)
    
    # 5. Check for urgency language patterns
    if _has_urgency_language(combined_text):
        phishing_score += 0.2

    # 6. Strong heuristic: presence of external URL + urgency/financial keywords ⇒ high confidence
    financial_tokens = ["bank", "invoice", "payment", "card", "upi", "tax", "refund", "account", "credit"]
    if url_detected and (any(tok in combined_text for tok in financial_tokens) or _has_urgency_language(combined_text) or "password" in combined_text):
        phishing_score = min(phishing_score + 0.6, 1.0)

    # 7. High-confidence pattern: password + reset + external URL
    if "password" in combined_text and "reset" in combined_text and len(urls) > 0:
        # strong indicator of credential phishing
        phishing_score = min(phishing_score + 0.6, 1.0)

    # 8. Boost when monetary amounts or refund/prize language present
    if re.search(r"\b(\$|₹|usd|rs\.|inr)\b|\d{2,3}(?:,\d{3})+|refund|prize|won|claim", combined_text, re.IGNORECASE):
        phishing_score = min(phishing_score + 0.2, 1.0)
    
    # Clamp to 0-1 range
    return min(max(phishing_score, 0.0), 1.0)


def _check_sender_reputation(sender: str) -> float:
    """
    Check sender email address for suspicious patterns.
    
    Returns:
        Score contribution (0.0 - 0.2)
    """
    score = 0.0
    
    # Check for suspicious sender patterns
    if not sender or "@" not in sender:
        return 0.2
    
    domain = sender.split("@")[1].lower()
    
    # Suspicious patterns
    if any(pattern in domain for pattern in ["noreply", "donotreply", "no-reply"]):
        score += 0.05
    
    # Generic free email for official domain
    if any(pattern in domain for pattern in ["gmail", "yahoo", "outlook"]):
        # Check if pretending to be a company
        if any(company in sender.lower() for company in ["bank", "paypal", "amazon", "apple"]):
            score += 0.15
    
    return min(score, 0.2)


def _has_urgency_language(text: str) -> bool:
    """Check if text contains urgency language."""
    urgency_patterns = [
        r"within .*(hour|day|week)",
        r"immediately",
        r"right now",
        r"don't delay",
        r"last chance",
        r"act fast",
    ]
    
    for pattern in urgency_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    
    return False
