from flask import Flask, jsonify, render_template, request
from detector import analyze_url

app = Flask(__name__)

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "CyberShield URL scanner", "mode": "local heuristics"})

@app.post("/api/scan")
def scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not isinstance(url, str):
        return jsonify({"error": "The 'url' field must be a string."}), 400
    try:
        result = analyze_url(url)
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Request is too large."}), 413

if __name__ == "__main__":
    # Keep local-only by default. Do not change to 0.0.0.0 unless you understand the exposure.
    app.run(host="127.0.0.1", port=5000, debug=False)
