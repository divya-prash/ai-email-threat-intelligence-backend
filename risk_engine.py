"""
Risk Engine for computing final risk score and classification.
"""


def compute_risk_score(rule_score: float, ml_score: float) -> float:
    """
    Compute final risk score combining rule-based score and ML model score.

    Formula: risk = (rule_score * 0.5) + (ml_score * 0.5)

    Args:
        rule_score: Score returned by rule engine (0.0 - 1.0)
        ml_score: Score returned by ML model (0.0 - 1.0)

    Returns:
        Final risk score (0.0 - 1.0)
    """
    risk_score = (rule_score * 0.5) + (ml_score * 0.5)
    return min(max(risk_score, 0.0), 1.0)


def classify_email(risk_score: float) -> str:
    """
    Classify email based on risk score.
    
    Classification:
    - < 0.5: Safe
    - < 0.9: Suspicious
    - >= 0.9: High Risk
    
    Args:
        risk_score: Final risk score (0.0 - 1.0)
        
    Returns:
        Classification string
    """
    if risk_score < 0.5:
        return "Safe"
    elif risk_score < 0.9:
        return "Suspicious"
    else:
        return "High Risk"
