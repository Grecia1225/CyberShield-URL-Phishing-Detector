import time
from collections import defaultdict, deque

from flask import Flask, jsonify, render_template, request

from detector import analyze_url, label_for
from enrich import enrich

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB request bodies

RATE_LIMIT, RATE_WINDOW = 20, 60  # 20 scans per minute per client
_hits = defaultdict(deque)

def _rate_limited():
    ip = (request.headers.get("X-Forwarded-For", request.remote_addr) or "?").split(",")[0].strip()
    now, q = time.time(), _hits[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return True
    q.append(now)
    return False

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "CyberShield URL scanner",
                    "mode": "heuristics + domain age + server location"})

@app.post("/api/scan")
def scan():
    if _rate_limited():
        return jsonify({"error": "Too many scans. Please wait a minute."}), 429
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not isinstance(url, str):
        return jsonify({"error": "The 'url' field must be a string."}), 400
    try:
        result = analyze_url(url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    try:
        extra = enrich(result["hostname"], result["normalized_url"],
                       result["registered_domain"], result["is_ip"])
    except Exception:  # lookups are best-effort; never fail the scan because of them
        extra = {"points": 0, "reasons": [], "details": {}, "force_high": False}

    score = min(100, result["risk_score"] + extra["points"])
    if extra["force_high"]:
        score = max(score, 90)
    if extra["reasons"]:
        result["reasons"] = [r for r in result["reasons"] if not r.startswith("No strong warning")]
        result["reasons"] += extra["reasons"]
    result.update(risk_score=score, label=label_for(score), details=extra["details"])
    return jsonify(result)

@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Request is too large."}), 413

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
