# 🛡️ AI-Based Phishing Email Detection System

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20App-lightgrey)
![ML](https://img.shields.io/badge/ML-Scikit--Learn-orange)
![Accuracy](https://img.shields.io/badge/Accuracy-98%25-brightgreen)

A full-stack AI-powered cybersecurity tool that detects phishing emails using Machine Learning, rule-based heuristics, and real-time URL reputation checking via the VirusTotal API.

## Features
- AI Classification — 98%+ accuracy on 5,500+ real emails
- Rule-Based Engine — detects urgency language, fake senders, credential theft
- URL Analyzer — scores suspicious links, extensions, IP-based URLs
- VirusTotal Integration — real-time URL check across 70+ antivirus engines
- Threat Score — combined 0-100 risk score with full breakdown
- Professional Dashboard — Flask web app

## Tech Stack
- Python 3.12
- Flask
- Scikit-learn + TF-IDF
- VirusTotal API v3
- Pandas, NumPy
- HTML, CSS, JavaScript

## Setup
git clone https://github.com/ishmeeeeet04/phishing-detector.git
cd phishing-detector
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python src/train_model.py
python app.py

Then open http://127.0.0.1:5000

## Model Performance
- Accuracy: 98.3%
- Precision (Phishing): 95%
- Recall (Phishing): 96%

## Author
Ishmeet Kaur
Final Year B.Tech
