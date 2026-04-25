"""
Spam Detection Engine using keyword scoring logic.
"""

# Common spam keywords with scores
SPAM_KEYWORDS = {
    "winner": 0.8,
    "click here": 0.9,
    "buy now": 0.7,
    "limited time": 0.6,
    "act now": 0.6,
    "urgent": 0.5,
    "congratulations": 0.7,
    "free": 0.6,
    "guarantee": 0.5,
    "no cost": 0.6,
    "risk free": 0.5,
    "special offer": 0.6,
    "unsubscribe": -0.1,  # Legitimate emails often have this
    "million": 0.8,
    "cash": 0.7,
    "prize": 0.8,
    "limited offer": 0.6,
    "act fast": 0.6,
    "apply now": 0.6,
    "cheap": 0.6,
    "discount": 0.6,
    "bargain": 0.5,
    "special promotion": 0.6,
    "save big": 0.6,
    "earn": 0.7,
    "earn money": 0.8,
    "work from home": 0.7,
    "investment opportunity": 0.7,
    "get paid": 0.7,
    "loan": 0.6,
    "credit": 0.6,
    "limited supply": 0.6,
    "act immediately": 0.6,
}


def detect_spam(subject: str, body: str) -> float:
    """
    Detect spam using keyword scoring logic.
    
    Args:
        subject: Email subject
        body: Email body
        
    Returns:
        Spam score (0.0 - 1.0)
    """
    combined_text = (subject + " " + body).lower()
    
    spam_score = 0.0
    keyword_count = 0
    max_keyword_score = 0.0
    
    for keyword, score in SPAM_KEYWORDS.items():
        if keyword in combined_text:
            keyword_count += 1
            max_keyword_score = max(max_keyword_score, score)
            spam_score += score
    
    # Normalize score
    if keyword_count > 0:
        # Average score with emphasis on highest scoring keyword
        spam_score = (spam_score / len(SPAM_KEYWORDS)) * 0.7 + (max_keyword_score * 0.3)
    
    # Clamp to 0-1 range
    return min(max(spam_score, 0.0), 1.0)
