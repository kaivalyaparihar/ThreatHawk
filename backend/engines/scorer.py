#backend\engines\scorer.py

def calculate_score(results: dict, ioc_type: str) -> tuple:
    """
    Calculate a weighted threat score from all integration results.
    Returns: (score: float, severity: str)

    Weights:
      - AbuseIPDB confidence score: 40%
      - VirusTotal detection ratio: 40%
      - Shodan: +10 if critical vulns found
      - URLScan: +10 if verdict is malicious
    """

    weighted_score = 0.0
    weight_total = 0.0

    # AbuseIPDB — 40% weight
    abuse = results.get("abuseipdb", {})
    if abuse.get("success") and abuse.get("data"):
        confidence = abuse["data"].get("abuseConfidenceScore", 0)
        weighted_score += float(confidence) * 0.4
        weight_total += 0.4

    # VirusTotal — 40% weight
    vt = results.get("virustotal", {})
    if vt.get("success") and vt.get("data"):
        malicious = vt["data"].get("malicious", 0)
        total = vt["data"].get("total_engines", 0)
        if total > 0:
            ratio = (malicious / total) * 100
            weighted_score += ratio * 0.4
            weight_total += 0.4

    # Shodan — bonus +10 for critical vulns
    shodan = results.get("shodan", {})
    if shodan.get("success") and shodan.get("data"):
        vulns = shodan["data"].get("vulns", [])
        if vulns:
            weighted_score += 10.0

    # URLScan — bonus +10 for malicious verdict
    urlscan = results.get("urlscan", {})
    if urlscan.get("success") and urlscan.get("data"):
        if urlscan["data"].get("is_malicious"):
            weighted_score += 10.0

    # If no weighted sources returned data, use a basic heuristic
    if weight_total > 0:
        # Normalise the weighted portion to 0-100
        base_score = weighted_score / weight_total * weight_total
        # Add bonus points (already in the score)
        score = min(weighted_score * (1.0 / weight_total) if weight_total < 0.8 else weighted_score, 100.0)
    else:
        score = weighted_score  # Only bonus points from Shodan/URLScan if any

    # Clamp to 0-100
    score = max(0.0, min(100.0, round(score, 1)))

    # Determine severity
    if score >= 75:
        severity = "Critical"
    elif score >= 50:
        severity = "High"
    elif score >= 25:
        severity = "Medium"
    else:
        severity = "Low"

    return score, severity
