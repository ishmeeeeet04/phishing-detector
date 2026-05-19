# phishing_detector.py
# Master detector: combines URL checker + email analyzer
# This is the brain that the Flask app will call later.

from url_checker    import calculate_threat_score as check_url, verdict as url_verdict
from email_analyzer import analyze_email, verdict

import re

def extract_urls(text):
    # Pull all URLs out of the email body automatically
    pattern = r'http[s]?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(pattern, text)

def scan_email(sender, subject, body):

    print("\n🔍 Scanning email...")

    # 1. Analyze the text
    email_score, email_reasons = analyze_email(sender, subject, body)

    # 2. Extract and scan every URL found in the body
    urls = extract_urls(body)
    url_scores = []
    url_reasons = []

    for url in urls:
        score, reasons = check_url(url)
        url_scores.append(score)
        for r in reasons:
            url_reasons.append(f"[URL: {url[:40]}...] {r}")

    # Take the worst URL score (most dangerous URL drives the score up)
    worst_url_score = max(url_scores) if url_scores else 0

    # 3. Final combined score
    if urls:
        final_score = int((email_score * 0.5) + (worst_url_score * 0.5))
    else:
        final_score = email_score

    final_score = min(final_score, 100)
    all_reasons = email_reasons + url_reasons

    return {
        "score":   final_score,
        "verdict": verdict(final_score),
        "reasons": all_reasons,
        "urls_found": urls
    }


if __name__ == "__main__":
    result = scan_email(
        sender  = "security@paypa1.com",
        subject = "URGENT: Verify your account NOW",
        body    = "Dear Customer, click here to verify your account: "
                  "http://paypal-login.verify-account.xyz/secure/update/password "
                  "or your account will be suspended within 24 hours."
    )

    print(f"\nFINAL SCORE:   {result['score']}/100")
    print(f"FINAL VERDICT: {result['verdict']}")
    print(f"URLS FOUND:    {result['urls_found']}")
    print("\nALL REASONS:")
    for r in result["reasons"]:
        print(f"  - {r}")