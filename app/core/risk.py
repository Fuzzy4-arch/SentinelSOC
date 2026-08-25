def calculate_risk(severity: str, attempts: int, rule: str) -> int:
    score = 0

    if severity == "LOW":
        score += 20
    elif severity == "MEDIUM":
        score += 40
    elif severity == "HIGH":
        score += 70
    elif severity == "CRITICAL":
        score += 90

    if attempts >= 5:
        score += 10

    if rule == "PASSWORD_SPRAYING":
        score += 10

    return min(score, 100)


def risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"