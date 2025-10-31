from flask import Flask, request, make_response, jsonify

app = Flask(__name__)

# ---------- helpers ----------

UNSAFE_METHODS = "GET, POST, PUT, DELETE, PATCH, OPTIONS"  # we'll also try TRACE for fun
POWERED_BY = "FlaskBad/9.9"
BACKEND = "internal-01"

def add_leaky_headers(resp):
    """
    Add headers that leak server/framework details on purpose.
    Also intentionally OMIT secure headers (CSP, HSTS, X-Frame-Options, etc.)
    """
    # Server banner (version leak)
    resp.headers["Server"] = "BadServer/0.1"

    # Framework / proxy / backend leaks
    resp.headers["X-Powered-By"] = POWERED_BY
    resp.headers["Via"] = "debug-proxy"
    resp.headers["X-Backend-Server"] = BACKEND

    # Intentionally do NOT set security headers like:
    # - Content-Security-Policy
    # - Strict-Transport-Security
    # - X-Frame-Options
    # - X-Content-Type-Options
    # - Referrer-Policy
    # - Permissions-Policy
    # - COEP/COOP/CORP

    return resp

def add_bad_cors(resp):
    """
    Deliberately misconfigure CORS:
    - If an Origin is sent, REFLECT it in ACAO (High)
    - Otherwise use wildcard (Medium)
    - Always set credentials=true (critical with wildcard)
    - Expose unsafe methods in ACAM
    """
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin  # reflection (High)
    else:
        resp.headers["Access-Control-Allow-Origin"] = "*"     # wildcard (Medium)

    resp.headers["Access-Control-Allow-Credentials"] = "true"  # credentials allowed
    resp.headers["Access-Control-Allow-Methods"] = UNSAFE_METHODS
    resp.headers["Access-Control-Max-Age"] = "3600"

    # Intentionally omit 'Vary: Origin' (Medium)
    # resp.headers["Vary"] = "Origin"

    return resp

def set_bad_cookies(resp):
    """
    Set server-side cookie WITHOUT Secure/HttpOnly/SameSite (bad).
    Also the root page sets a JS cookie client-side.
    """
    resp.headers.add("Set-Cookie", "sessionid=abc123; Path=/")  # missing Secure, HttpOnly, SameSite
    return resp

def make_html(body):
    html = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>Bad Test Server</title></head>
<body>
<h1>Bad Test Server</h1>
<p>{body}</p>
<!-- Intentionally set JS cookie without flags -->
<script>document.cookie = "jsbad=1; path=/";</script>
</body>
</html>"""
    return html

# ---------- routes ----------

@app.route("/", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"])
def index():
    # For TRACE, echo request (simulated)
    if request.method == "TRACE":
        resp = make_response(request.environ.get("RAW_URI", "/"), 200)
        resp.mimetype = "message/http"
    else:
        body = "This page intentionally misconfigured for testing."
        resp = make_response(make_html(body), 200)
        resp.mimetype = "text/html"

    # Add intentionally bad pieces
    resp = add_leaky_headers(resp)
    resp = add_bad_cors(resp)
    resp = set_bad_cookies(resp)

    # For preflight OPTIONS, ensure Allow header present
    if request.method == "OPTIONS":
        resp.headers["Allow"] = UNSAFE_METHODS + ", TRACE"

    return resp

@app.route("/cookies/anything", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"])
def cookies_anything():
    # Similar to index but different path (to mimic httpbin style)
    if request.method == "TRACE":
        resp = make_response(request.environ.get("RAW_URI", "/cookies/anything"), 200)
        resp.mimetype = "message/http"
    else:
        body = "Cookie path (intentionally misconfigured)."
        resp = make_response(make_html(body), 404)  # return 404 to test non-200 behavior
        resp.mimetype = "text/html"

    resp = add_leaky_headers(resp)
    resp = add_bad_cors(resp)
    resp = set_bad_cookies(resp)

    if request.method == "OPTIONS":
        resp.headers["Allow"] = UNSAFE_METHODS + ", TRACE"

    return resp

@app.route("/api/data", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"])
def api_data():
    # Return JSON but keep bad headers/cors/cookies the same
    if request.method == "TRACE":
        resp = make_response(request.environ.get("RAW_URI", "/api/data"), 200)
        resp.mimetype = "message/http"
    else:
        data = {"ok": True, "note": "Insecure CORS and cookies here too."}
        resp = make_response(jsonify(data), 200)

    resp = add_leaky_headers(resp)
    resp = add_bad_cors(resp)
    resp = set_bad_cookies(resp)

    if request.method == "OPTIONS":
        resp.headers["Allow"] = UNSAFE_METHODS + ", TRACE"

    return resp

# Catch-all for other paths (also misconfigured)
@app.route("/<path:rest>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"])
def catch_all(rest):
    if request.method == "TRACE":
        resp = make_response(request.environ.get("RAW_URI", f"/{rest}"), 200)
        resp.mimetype = "message/http"
    else:
        body = f"Catch-all route for /{rest} (intentionally misconfigured)."
        resp = make_response(make_html(body), 200)
        resp.mimetype = "text/html"

    resp = add_leaky_headers(resp)
    resp = add_bad_cors(resp)
    resp = set_bad_cookies(resp)

    if request.method == "OPTIONS":
        resp.headers["Allow"] = UNSAFE_METHODS + ", TRACE"

    return resp

if __name__ == "__main__":
    # Run HTTP only (so your SSL/TLS check reports 'HTTPS not supported' or flags issues).
    # If you want to test HTTPS later, generate a self-signed cert and start with ssl_context.
    app.run(host="127.0.0.1", port=5000, debug=False)
    # For self-signed HTTPS (optional later):
    # app.run(host="127.0.0.1", port=5001, ssl_context=("cert.pem", "key.pem"))
