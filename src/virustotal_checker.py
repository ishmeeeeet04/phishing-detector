# virustotal_checker.py
# Checks any URL against VirusTotal's database of
# millions of known malicious URLs in real time.

import requests
import hashlib
import os
import time
from dotenv import load_dotenv

# Rate limiter — free VirusTotal API allows only 4 requests per minute
_last_request_time = 0
_MIN_REQUEST_INTERVAL = 16  # wait 16 seconds between requests (60s ÷ 4 = 15s + 1s buffer)

def _wait_for_rate_limit():
    global _last_request_time
    now = time.time()
    elapsed = now - _last_request_time
    if elapsed < _MIN_REQUEST_INTERVAL:
        wait_time = _MIN_REQUEST_INTERVAL - elapsed
        print(f"[VirusTotal] Waiting {wait_time:.1f}s to respect rate limit...")
        time.sleep(wait_time)
    _last_request_time = time.time()

# Load API key from .env file
load_dotenv()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

VT_URL_ENDPOINT  = "https://www.virustotal.com/api/v3/urls"
VT_BASE_ENDPOINT = "https://www.virustotal.com/api/v3"

def check_url_virustotal(url):
    """
    Sends a URL to VirusTotal and returns:
    - vt_score: 0-100 danger score
    - malicious_count: how many engines flagged it
    - total_engines: how many engines scanned it
    - verdict: CLEAN / SUSPICIOUS / MALICIOUS
    - details: human readable summary
    """

    if not API_KEY:
        return {
            "vt_score":        0,
            "malicious_count": 0,
            "total_engines":   0,
            "verdict":         "API_KEY_MISSING",
            "details":         "No VirusTotal API key found in .env file"
        }
        _wait_for_rate_limit() 

    headers = {
        "x-apikey": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        # Step 1: Submit the URL for scanning
        response = requests.post(
            VT_URL_ENDPOINT,
            headers=headers,
            data=f"url={url}",
            timeout=10
        )

        if response.status_code != 200:
            return _error_result(f"Submission failed: HTTP {response.status_code}")

        # Step 2: Get the analysis ID from response
        analysis_id = response.json()["data"]["id"]

        # Step 3: Wait briefly then fetch the result
        # VirusTotal needs a moment to scan
        time.sleep(2)

        result_response = requests.get(
            f"{VT_BASE_ENDPOINT}/analyses/{analysis_id}",
            headers={"x-apikey": API_KEY},
            timeout=10
        )

        if result_response.status_code != 200:
            return _error_result(f"Result fetch failed: HTTP {result_response.status_code}")

        stats = result_response.json()["data"]["attributes"]["stats"]

        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless",   0)
        undetected = stats.get("undetected", 0)

        total_engines = malicious + suspicious + harmless + undetected

        # Calculate score: malicious engines weighted more than suspicious
        if total_engines > 0:
            danger_ratio = (malicious * 1.0 + suspicious * 0.5) / total_engines
            vt_score = int(danger_ratio * 100)
        else:
            vt_score = 0

        # Verdict
        if malicious >= 3:
            verdict = "MALICIOUS"
        elif malicious >= 1 or suspicious >= 3:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        details = (
            f"VirusTotal: {malicious} engines flagged as malicious, "
            f"{suspicious} suspicious out of {total_engines} total engines"
        )

        return {
            "vt_score":        vt_score,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines":   total_engines,
            "verdict":         verdict,
            "details":         details
        }

    except requests.exceptions.Timeout:
        return _error_result("VirusTotal request timed out")
    except requests.exceptions.ConnectionError:
        return _error_result("Cannot connect to VirusTotal — check internet")
    except Exception as e:
        return _error_result(f"Unexpected error: {str(e)}")


def _error_result(message):
    return {
        "vt_score":        0,
        "malicious_count": 0,
        "total_engines":   0,
        "verdict":         "ERROR",
        "details":         message
    }


# ── Test ───────────────────────────────────────────────────────
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://paypal-login.verify-account.xyz"
    ]

    for url in test_urls:
        print(f"\nChecking: {url}")
        result = check_url_virustotal(url)
        print(f"  Verdict:   {result['verdict']}")
        print(f"  VT Score:  {result['vt_score']}/100")
        print(f"  Details:   {result['details']}")