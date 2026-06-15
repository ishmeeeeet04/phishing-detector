# email_analyzer.py
import re

URGENCY_WORDS = [
    "urgent", "immediately", "action required", "act now",
    "within 24 hours", "expires today", "last chance", "final notice"
]

THREAT_WORDS = [
    "suspended", "terminated", "blocked", "unauthorized",
    "locked", "disabled", "compromised", "unusual activity"
]

REWARD_WORDS = [
    "winner", "won", "prize", "reward", "free", "gift",
    "congratulations", "selected", "lucky", "claim now"
]

CREDENTIAL_WORDS = [
    "verify your account", "confirm your identity", "update your password",
    "enter your details", "validate your", "click here to verify",
    "sign in to confirm"
]

REQUEST_WORDS = [
    "click here", "click the link", "click below",
    "open the attachment", "download the file", "call this number"
]


def check_sender(sender_email):
    score = 0
    reasons = []

    if not sender_email or sender_email.strip() == "":
        score += 20
        reasons.append("No sender address found")
        return score, reasons

    sender_lower = sender_email.lower()

    # Check for typosquatted brand names
    fake_brands = [
        ("paypal", "paypa1"),
        ("amazon", "amaz0n"),
        ("google", "g00gle"),
        ("microsoft", "micros0ft"),
        ("apple", "app1e"),
        ("netflix", "netf1ix"),
    ]
    for real, fake in fake_brands:
        if fake in sender_lower:
            score += 40
            reasons.append(f"Sender domain looks like a fake '{real}' address")

    # Check for brand impersonation with wrong domain
    brand_domains = {
        "paypal":    "paypal.com",
        "amazon":    "amazon.com",
        "google":    "google.com",
        "microsoft": "microsoft.com",
        "apple":     "apple.com",
        "netflix":   "netflix.com",
        "bank":      None,
    }
    domain_part = sender_lower.split("@")[-1] if "@" in sender_lower else ""
    for brand, real_domain in brand_domains.items():
        if brand in domain_part:
            if real_domain is None or not (
                domain_part == real_domain or
                domain_part.endswith("." + real_domain)
            ):
                score += 25
                reasons.append(
                    f"Sender pretends to be '{brand}' but uses a suspicious domain"
                )
                break

    # Check for randomly generated sender names
    local_part = sender_lower.split("@")[0]
    if len(local_part) > 15 and re.search(r'\d{4,}', local_part):
        score += 15
        reasons.append("Sender name looks randomly generated")

    return score, reasons


def analyze_text(subject, body):
    score = 0
    reasons = []

    full_text = (subject + " " + body).lower()

    categories = [
        (URGENCY_WORDS,    "urgency",              15),
        (THREAT_WORDS,     "threats/fear",         20),
        (REWARD_WORDS,     "fake rewards",         15),
        (CREDENTIAL_WORDS, "credential theft",     25),
        (REQUEST_WORDS,    "suspicious requests",  20),
    ]

    for word_list, category_name, points_per_hit in categories:
        hits = []
        for word in word_list:
            if word in full_text:
                hits.append(word)

        if hits:
            category_score = min(len(hits) * points_per_hit, points_per_hit * 2)
            score += category_score
            reasons.append(
                f"Found {category_name} language: {', '.join(hits[:3])}"
            )

    # Check for ALL CAPS words
    caps_words = re.findall(r'\b[A-Z]{4,}\b', subject + " " + body)
    if len(caps_words) >= 2:
        score += 10
        reasons.append(
            f"Excessive CAPS used to create urgency: {', '.join(caps_words[:3])}"
        )

    # Check for generic greetings
    generic_greetings = [
        "dear customer", "dear user", "dear member",
        "dear account holder", "hello user", "dear sir"
    ]
    for greeting in generic_greetings:
        if greeting in full_text:
            score += 15
            reasons.append(
                f"Generic greeting used: '{greeting}' — real companies use your name"
            )
            break

    return min(score, 100), reasons


def analyze_email(sender, subject, body):
    sender_score, sender_reasons = check_sender(sender)
    text_score,   text_reasons   = analyze_text(subject, body)

    combined_score = int((text_score * 0.7) + (sender_score * 0.3))
    combined_score = min(combined_score, 100)

    all_reasons = sender_reasons + text_reasons

    return combined_score, all_reasons


def verdict(score):
    if score >= 60:
        return "PHISHING"
    elif score >= 20:
        return "SUSPICIOUS"
    else:
        return "SAFE"


if __name__ == "__main__":
    test_emails = [
        {
            "sender":  "noreply@google.com",
            "subject": "Your monthly account summary",
            "body":    "Hi John, here is your account activity for this month."
        },
        {
            "sender":  "security@paypa1.com",
            "subject": "URGENT: Your account has been suspended",
            "body":    "Dear Customer, unusual activity was detected. "
                       "Your account is locked. Click here to verify your account immediately "
                       "or it will be terminated within 24 hours."
        },
        {
            "sender":  "prizes@lucky-winners.xyz",
            "subject": "Congratulations! You have WON a FREE gift!",
            "body":    "Dear user, you have been selected as our lucky winner. "
                       "Claim now! Click the link below to confirm your identity."
        },
    ]

    for email in test_emails:
        score, reasons = analyze_email(
            email["sender"],
            email["subject"],
            email["body"]
        )
        print(f"\n{'='*55}")
        print(f"FROM:    {email['sender']}")
        print(f"SUBJECT: {email['subject']}")
        print(f"SCORE:   {score}/100  |  VERDICT: {verdict(score)}")
        print("REASONS:")
        for r in reasons:
            print(f"  - {r}")