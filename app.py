# app.py
# This is the web server for our phishing detector.
# Flask takes requests from the browser and sends back results.

from flask import Flask, render_template, request, jsonify
import sys
import os

# This line lets app.py find files inside the src/ folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from phishing_detector import scan_email

# Create the Flask app
app = Flask(__name__)

# --- ROUTES ---
# A route is a URL path. When browser visits that path, Flask runs that function.

@app.route("/")
def home():
    # When user visits http://localhost:5000/
    # Flask looks for templates/index.html and sends it to the browser
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json

    if not data:
        return jsonify({"error": "No data received"}), 400

    sender  = str(data.get("sender",  "")).strip()
    subject = str(data.get("subject", "")).strip()
    body    = str(data.get("body",    "")).strip()

    # Reject if both subject and body are empty
    if not subject and not body:
        return jsonify({"error": "Subject or body is required"}), 400

    # Reject if input is too large (prevents server overload)
    if len(body) > 50000:
        return jsonify({"error": "Email body too large (max 50,000 characters)"}), 400

    if len(subject) > 500:
        return jsonify({"error": "Subject too long (max 500 characters)"}), 400

    try:
        result = scan_email(sender, subject, body)
        return jsonify(result)
    except Exception as e:
        # Never expose internal errors to the client
        print(f"Scan error: {e}")
        return jsonify({"error": "Analysis failed. Please try again."}), 500
if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)