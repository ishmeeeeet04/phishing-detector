# 🛡️ AI-Based Phishing Email Detection System

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20App-lightgrey)
![ML](https://img.shields.io/badge/ML-Scikit--Learn-orange)
![API](https://img.shields.io/badge/API-VirusTotal-red)
![Accuracy](https://img.shields.io/badge/Accuracy-98%25-brightgreen)
![Status](https://img.shields.io/badge/Status-Live-success)

> A full-stack AI-powered cybersecurity tool that detects phishing emails
> using Machine Learning, rule-based heuristics, and real-time URL
> reputation checking via the VirusTotal API.

---

## 🎯 Features

- ✅ **AI Classification** — Logistic Regression model trained on 5,500+ real emails with 98%+ accuracy
- ✅ **Rule-Based Engine** — Detects urgency language, fake sender domains, credential theft patterns
- ✅ **URL Analyzer** — Scores URLs for suspicious keywords, bad extensions, IP-based links
- ✅ **VirusTotal Integration** — Real-time URL reputation check across 70+ antivirus engines
- ✅ **Threat Score** — Combined 0–100 risk score with full breakdown
- ✅ **Professional Dashboard** — Clean dark-mode web UI built with Flask

---

## 🖥️ Dashboard Preview

| Input | Result |
|---|---|
| Paste any email | Instant threat score 0–100 |
| Sender + Subject + Body | SAFE / SUSPICIOUS / PHISHING verdict |
| URLs auto-extracted | VirusTotal scan per URL |
| All signals combined | Breakdown: AI + Rules + URL scores |

---

## 🏗️ Architecture

```
Email Input (sender + subject + body)
          │
          ▼
┌─────────────────────────────┐
│        Preprocessing         │
│  Extract URLs · Clean text   │
└──────────────┬───────────────┘
               │
     ┌─────────┼──────────┐
     ▼         ▼          ▼
  ML Model   Rules     URL Analysis
  (TF-IDF)   Engine    + VirusTotal
     │         │          │
     └─────────┴──────────┘
               │
               ▼
        Threat Score (0–100)
               │
     ┌─────────┴──────────┐
   SAFE     SUSPICIOUS   PHISHING
  (0–30)     (31–69)     (70–100)
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Language | Python 3.12 | Core development |
| ML | Scikit-learn, TF-IDF | Email classification |
| Backend | Flask | REST API + web server |
| Frontend | HTML, CSS, JavaScript | Interactive dashboard |
| Security API | VirusTotal API v3 | Live URL reputation checking |
| Data | Pandas, NumPy | Dataset processing |
| Storage | Pickle | Trained model persistence |

---

## 📁 Project Structure

```
phishing-detector/
├── src/
│   ├── url_checker.py          # URL heuristic scoring
│   ├── email_analyzer.py       # Text + sender analysis
│   ├── phishing_detector.py    # Master detection engine
│   ├── virustotal_checker.py   # VirusTotal API integration
│   └── train_model.py          # ML model training
├── models/
│   ├── phishing_model.pkl      # Trained classifier
│   └── vectorizer.pkl          # TF-IDF vectorizer
├── templates/
│   └── index.html              # Web dashboard
├── data/
│   └── emails.tsv              # Training dataset (5,572 emails)
├── app.py                      # Flask web server
├── requirements.txt            # Dependencies
└── README.md                   # This file
```

---

## ⚙️ Setup and Installation

```bash
# 1. Clone the repository
git clone https://github.com/ishmeeeeet04/phishing-detector.git
cd phishing-detector

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Add your VirusTotal API key
# Create a .env file and add:
# VIRUSTOTAL_API_KEY=your_key_here

# 5. Train the model
python src/train_model.py

# 6. Run the app
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

---

## 🧪 Sample Test Case

**Input:**
- Sender: `security@paypa1.com`
- Subject: `URGENT: Your account has been suspended`
- Body: `Dear Customer, verify immediately or your account will be terminated within 24 hours. http://paypal-login.verify-account.xyz/secure`

**Output:**
```
Score:   94/100
Verdict: PHISHING
Reasons:
  - ML confidence: 96.2% phishing
  - Sender domain looks like a fake 'paypal' address
  - Found urgency language: urgent, within 24 hours
  - Found threats/fear language: suspended, terminated
  - VirusTotal: 14 engines flagged URL as malicious
```

---

## 📊 Model Performance

| Metric | Legitimate | Phishing |
|---|---|---|
| Precision | 99% | 95% |
| Recall | 99% | 96% |
| F1-Score | 99% | 96% |
| **Overall Accuracy** | **98.3%** | |

Trained on 5,572 real emails from the SMS Spam Collection dataset.

---

## 🔮 Future Improvements

- Attachment scanning for PDF and DOCX malware detection
- Email header analysis with SPF, DKIM, DMARC validation
- Browser extension for real-time Gmail scanning
- Docker containerization for easy deployment
- Database logging for scan history and analytics

---

## 👤 Author

**Ishmeet Kaur**
Final Year B.Tech — Computer Science / Cybersecurity
[GitHub](https://github.com/ishmeeeeet04)

---

## ⭐ If you found this useful, please star the repository!
