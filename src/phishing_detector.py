# phishing_detector.py (with VirusTotal)
from url_checker         import calculate_threat_score as check_url
from email_analyzer      import analyze_email, verdict
from virustotal_checker  import check_url_virustotal    # ← new import

import re
import pickle
import os

MODEL_PATH      = os.path.join("models", "phishing_model.pkl")
VECTORIZER_PATH = os.path.join("models", "vectorizer.pkl")

ml_model   = None
vectorizer = None

def load_model():
    global ml_model, vectorizer
    try:
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            with open(MODEL_PATH, "rb") as f:
                ml_model = pickle.load(f)
            with open(VECTORIZER_PATH, "rb") as f:
                vectorizer = pickle.load(f)
            print("ML model loaded.")
        else:
            print("No trained model found. Run train_model.py first.")
    except Exception as e:
        print("Model loading failed:", e)

load_model()


def get_ml_score(subject, body):
    global ml_model, vectorizer
    if ml_model is None or vectorizer is None:
        return 0, "ML model not available"
    try:
        features             = vectorizer.transform([subject + " " + body])
        proba                = ml_model.predict_proba(features)[0]
        phishing_probability = proba[1]
        return int(phishing_probability * 100), f"ML confidence: {phishing_probability:.1%}"
    except Exception as e:
        return 0, f"ML error: {str(e)}"


def extract_urls(text):
    return re.findall(r'http[s]?://[^\s<>"{}|\\^`\[\]]+', text)


def scan_email(sender, subject, body, use_virustotal=True):

    # 1. Rule-based analysis
    rule_score, rule_reasons = analyze_email(sender, subject, body)

    # 2. ML prediction
    ml_score, ml_reason = get_ml_score(subject, body)

    # 3. URL analysis — rule-based + VirusTotal
    urls        = extract_urls(body)
    url_scores  = []
    url_reasons = []
    vt_results  = []

    for url in urls:
        # Rule-based URL score
        rule_url_score, rule_url_reasons = check_url(url)
        url_scores.append(rule_url_score)
        for r in rule_url_reasons:
            url_reasons.append(f"[URL rules] {r}")

        # VirusTotal check (only if enabled)
        if use_virustotal:
            vt = check_url_virustotal(url)
            url_scores.append(vt["vt_score"])
            url_reasons.append(f"[VirusTotal] {vt['details']}")
            vt_results.append({
                "url":     url,
                "verdict": vt["verdict"],
                "score":   vt["vt_score"]
            })

    worst_url_score = max(url_scores) if url_scores else 0

    # 4. Weighted final score
    if urls:
        final_score = int(
            (ml_score        * 0.35) +
            (rule_score      * 0.30) +
            (worst_url_score * 0.35)
        )
    else:
        final_score = int(
            (ml_score   * 0.50) +
            (rule_score * 0.50)
        )

    final_score = min(final_score, 100)

    all_reasons = [ml_reason] + rule_reasons + url_reasons

    return {
        "score":       final_score,
        "verdict":     verdict(final_score),
        "reasons":     all_reasons,
        "urls_found":  urls,
        "vt_results":  vt_results,
        "breakdown": {
            "ml_score":   ml_score,
            "rule_score": rule_score,
            "url_score":  worst_url_score
        }
    }


if __name__ == "__main__":
    result = scan_email(
        sender  = "security@paypa1.com",
        subject = "URGENT: Your account has been suspended",
        body    = "Dear Customer, verify: http://paypal-login.verify-account.xyz/secure "
                  "or your account will be terminated within 24 hours.",
        use_virustotal=True
    )
    print(f"\nFINAL SCORE:   {result['score']}/100")
    print(f"FINAL VERDICT: {result['verdict']}")
    print(f"BREAKDOWN:     {result['breakdown']}")
    print(f"VT RESULTS:    {result['vt_results']}")
    print("\nREASONS:")
    for r in result["reasons"]:
        print(f"  - {r}")