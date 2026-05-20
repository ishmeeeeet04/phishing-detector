# url_checker.py
# This is the first component of our phishing detector.
# It looks at a URL and decides how suspicious it is.

import re  # re = regular expressions, a tool for pattern matching in text

# --- SUSPICIOUS SIGNALS ---
# These are patterns real attackers use in URLs

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update",
    "banking", "confirm", "password", "signin", "ebayisapi",
    "webscr", "free", "lucky", "winner", "click"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".ru", ".cn", ".top", ".work", ".click"
]

def check_ip_in_url(url):
    # Attackers sometimes use raw IP addresses instead of domain names
    # Example: http://192.168.1.1/login  ← looks suspicious
    pattern = r"http[s]?://(\d{1,3}\.){3}\d{1,3}"
    return bool(re.search(pattern, url))

def check_url_length(url):
    # Phishing URLs are often very long to hide the real destination
    return len(url) > 75

def count_suspicious_keywords(url):
    url_lower = url.lower()  # convert to lowercase so "Login" and "login" both match
    count = 0
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            count += 1
    return count

def check_suspicious_tld(url):
    url_lower = url.lower()
    for tld in SUSPICIOUS_TLDS:
        if url_lower.endswith(tld) or tld + "/" in url_lower:
            return True
    return False

def count_dots(url):
    # Too many dots in a URL = subdomain stacking trick
    # Example: paypal.secure.login.attacker.com
    return url.count(".") > 3

def calculate_threat_score(url):
    score = 0
    reasons = []  # we'll collect WHY it's suspicious

    if check_ip_in_url(url):
        score += 30
        reasons.append("Uses raw IP address instead of domain name")

    if check_url_length(url):
        score += 20
        reasons.append(f"URL is very long ({len(url)} characters)")

    keyword_count = count_suspicious_keywords(url)
    if keyword_count > 0:
        score += keyword_count * 15
        reasons.append(f"Contains {keyword_count} suspicious keyword(s)")

    if check_suspicious_tld(url):
        score += 20
        reasons.append("Uses a suspicious domain extension")

    if count_dots(url):
        score += 15
        reasons.append("Too many dots — possible subdomain stacking")

    # Cap score at 100
    score = min(score, 100)

    return score, reasons

def verdict(score):
    if score >= 70:
        return "PHISHING"
    elif score >= 30:
        return "SUSPICIOUS"
    else:
        return "SAFE"

# --- TEST IT ---
# This block only runs when you run THIS file directly
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login/verify",
        "http://paypal-secure-login.verify-account.xyz/update/password/confirm",
        "https://amazon.com/orders"
    ]

    for url in test_urls:
        score, reasons = calculate_threat_score(url)
        print(f"\nURL: {url}")
        print(f"Score: {score}/100")
        print(f"Verdict: {verdict(score)}")
        if reasons:
            print("Reasons:")
            for r in reasons:
                print(f"  - {r}")
               