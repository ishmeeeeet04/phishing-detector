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
    # When the frontend submits the email form, it hits this route
    # request.json contains the data sent from the browser
    data = request.json

    sender  = data.get("sender", "")
    subject = data.get("subject", "")
    body    = data.get("body", "")

    # Run our detector engine
    result = scan_email(sender, subject, body)

    # Send result back to browser as JSON
    return jsonify(result)
if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)