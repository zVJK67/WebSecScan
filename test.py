import requests

CHECKS = {
    "strict-transport-security": lambda v: v is not None and "max-age" in v.lower(),
    "content-security-policy": lambda v: v is not None and len(v) > 0,
    "x-frame-options": lambda v: v is not None and v.upper() in ("DENY","SAMEORIGIN"),
    "x-content-type-options": lambda v: v is not None and v.lower() == "nosniff",
    "referrer-policy": lambda v: v is not None,
    "permissions-policy": lambda v: v is not None,  # or validate specific directives
}

def analyze_headers(url):
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
        results = {}
        for header, test in CHECKS.items():
            val = headers.get(header)
            results[header] = {"present": val is not None, "value": val, "passes": test(val)}
        return results
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    site = "https://juice-shop.herokuapp.com/"
    print(analyze_headers(site))
