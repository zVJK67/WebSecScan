# analyze http headers
from colorama import Fore

def analyze_security_headers(headers):
    """
    Analyze HTTP response headers for common security misconfigurations.
    Returns a list of findings (each as a dict with name, status, severity, and recommendation).
    """
    findings = []

    # --- Content Security Policy (CSP) ---
    csp = headers.get("Content-Security-Policy")
    if not csp:
        findings.append({
            "Header": "Content-Security-Policy",
            "Status": "Missing",
            "Severity": "High",
            "Recommendation": "Add a CSP header to control sources of scripts, styles, and media."
        })
    else:
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            findings.append({
                "Header": "Content-Security-Policy",
                "Status": "Weak",
                "Severity": "Medium",
                "Recommendation": "Avoid using 'unsafe-inline' or 'unsafe-eval' in CSP for stronger XSS protection."
            })
        else:
            findings.append({
                "Header": "Content-Security-Policy",
                "Status": "Present",
                "Severity": "Low",
                "Recommendation": "CSP implemented properly."
            })

    # --- Strict Transport Security (HSTS) ---
    if "Strict-Transport-Security" not in headers:
        findings.append({
            "Header": "Strict-Transport-Security",
            "Status": "Missing",
            "Severity": "High",
            "Recommendation": "Enable HSTS to enforce HTTPS and protect against downgrade attacks."
        })

    # --- X-Frame-Options ---
    if "X-Frame-Options" not in headers:
        findings.append({
            "Header": "X-Frame-Options",
            "Status": "Missing",
            "Severity": "Medium",
            "Recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN to protect against clickjacking."
        })

    # --- X-Content-Type-Options ---
    if "X-Content-Type-Options" not in headers:
        findings.append({
            "Header": "X-Content-Type-Options",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Add X-Content-Type-Options: nosniff to prevent MIME-type confusion."
        })

    # --- Referrer Policy ---
    if "Referrer-Policy" not in headers:
        findings.append({
            "Header": "Referrer-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Add Referrer-Policy: no-referrer-when-downgrade or strict-origin to control referrer data leakage."
        })

    # --- Permissions Policy ---
    if "Permissions-Policy" not in headers:
        findings.append({
            "Header": "Permissions-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Use Permissions-Policy to control access to browser features (e.g., camera, microphone)."
        })

    return findings


def print_findings(findings):
    """
    Print findings in a readable format with color.
    """
    print(Fore.CYAN + "\n🛡️ Security Header Analysis Results:\n")
    for f in findings:
        severity_color = {
            "High": Fore.RED,
            "Medium": Fore.YELLOW,
            "Low": Fore.GREEN
        }.get(f["Severity"], Fore.WHITE)

        print(f"{severity_color}{f['Header']}: {f['Status']} ({f['Severity']})")
        print(Fore.WHITE + f"   ↳ Recommendation: {f['Recommendation']}\n")
