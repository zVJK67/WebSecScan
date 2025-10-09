# get_header.py

import requests

def get_request(url, method="GET"):
    """
    Send an HTTP request to the given URL.
    Default method is GET, but can also use HEAD, OPTIONS, etc.
    Returns: response object or None if error
    """
    try:
        if method.upper() == "GET":
            response = requests.get(url, timeout=10)
        elif method.upper() == "HEAD":
            response = requests.head(url, timeout=10)
        elif method.upper() == "OPTIONS":
            response = requests.options(url, timeout=10)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        return response

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed for {url}: {e}")
        return None


def parse_headers(response):
    """
    Parse headers from a requests response object.
    Returns them as a dictionary.
    """
    if response is None:
        return {}

    return dict(response.headers)


def print_headers(headers_dict):
    """
    Print headers line by line (clean, no extra spaces).
    """
    print("\n📋 Response Headers:\n")
    for k, v in headers_dict.items():
        print(f"{k}: {v}")


def get_allowed_methods(url):
    """
    Check which HTTP methods are allowed by the server.
    Uses OPTIONS request.
    """
    response = get_request(url, method="OPTIONS")
    if response and "Allow" in response.headers:
        return [m.strip() for m in response.headers["Allow"].split(",")]
    return []


# analyze_header.py

from colorama import Fore, Style

def analyze_security_headers(headers):
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
                "Status": "Misconfigured",
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
    xfo = headers.get("X-Frame-Options")
    if not xfo:
        findings.append({
            "Header": "X-Frame-Options",
            "Status": "Missing",
            "Severity": "Medium",
            "Recommendation": "Add X-Frame-Options: DENY to protect against clickjacking."
        })
    else:
        if xfo.strip().upper() != "DENY":
            findings.append({
                "Header": "X-Frame-Options",
                "Status": "Misconfigured",
                "Severity": "Medium",
                "Recommendation": "Set X-Frame-Options to DENY for maximum protection against clickjacking."
            })

    # --- X-XSS-Protection ---
    xxp = headers.get("X-XSS-Protection")
    if not xxp:
        findings.append({
            "Header": "X-XSS-Protection",
            "Status": "Missing",
            "Severity": "Medium",
            "Recommendation": "Add X-XSS-Protection: 1; mode=block for legacy browser XSS mitigation."
        })
    else:
        if xxp.strip() != "1; mode=block":
            findings.append({
                "Header": "X-XSS-Protection",
                "Status": "Misconfigured",
                "Severity": "Medium",
                "Recommendation": "Set X-XSS-Protection: 1; mode=block to enable basic XSS protection in older browsers."
            })

    # --- X-Content-Type-Options ---
    xcto = headers.get("X-Content-Type-Options")
    if not xcto:
        findings.append({
            "Header": "X-Content-Type-Options",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Add X-Content-Type-Options: nosniff to prevent MIME-type confusion."
        })
    else:
        if xcto.strip().lower() != "nosniff":
            findings.append({
                "Header": "X-Content-Type-Options",
                "Status": "Misconfigured",
                "Severity": "Low",
                "Recommendation": "Set X-Content-Type-Options: nosniff to prevent MIME-type confusion."
            })

    # --- Referrer Policy ---
    rp = headers.get("Referrer-Policy")
    if not rp:
        findings.append({
            "Header": "Referrer-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin to control referrer data leakage."
        })
    else:
        if rp.strip().lower() != "strict-origin-when-cross-origin":
            findings.append({
                "Header": "Referrer-Policy",
                "Status": "Misconfigured",
                "Severity": "Low",
                "Recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin to control referrer data leakage."
            })

    # --- Permissions Policy ---
    if "Permissions-Policy" not in headers:
        findings.append({
            "Header": "Permissions-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Use Permissions-Policy to control access to browser features (e.g., camera, microphone)."
        })

    # --- Server header exposure ---
    if "Server" in headers:
        findings.append({
            "Header": "Server",
            "Status": "Misconfigured",
            "Severity": "Medium",
            "Recommendation": "Avoid exposing the Server header to reduce information disclosure."
        })

        # --- Allow header exposure ---
    if "Allow" in headers:
        findings.append({
            "Header": "Allow",
            "Status": "Misconfigured",
            "Severity": "Medium",
            "Recommendation": "Avoid exposing the 'Allow' header as it reveals supported HTTP methods."
        })

    return findings

def print_findings(findings):
    missing = [f for f in findings if f["Status"].lower() == "missing"]
    misconfigured = [f for f in findings if f["Status"].lower() == "misconfigured"]

    total_issues = len(missing) + len(misconfigured)

    print(Fore.CYAN + "\n🛡️ Security Header Analysis Results" + Style.RESET_ALL)
    print("====================================")
    print(Fore.WHITE + f"Total Issues Detected: {Fore.YELLOW}{total_issues}{Style.RESET_ALL}")
    print(Fore.WHITE + f"Missing Headers: {Fore.RED}{len(missing)}{Style.RESET_ALL} | Misconfigured: {Fore.YELLOW}{len(misconfigured)}\n")

    def print_group(title, items, color):
        if not items:
            return
        print(color + f"{title}:")
        print(color + "────────────────────────" + Style.RESET_ALL)
        for i, f in enumerate(items, 1):
            severity_color = {
                "High": Fore.RED,
                "Medium": Fore.YELLOW,
                "Low": Fore.GREEN
            }.get(f["Severity"], Fore.WHITE)

            print(f"{Fore.WHITE}{i}. {f['Header']}")
            print(f"   {severity_color}Severity: {f['Severity']}")
            print(f"{Fore.CYAN}   Recommendation: {f['Recommendation']}\n")

    print_group("🚫 Missing Headers", missing, Fore.RED)
    print_group("⚠️ Misconfigured Headers", misconfigured, Fore.YELLOW)

    if not missing and not misconfigured:
        print(Fore.GREEN + "\n✅ All security headers are properly configured!\n" + Style.RESET_ALL)

def analyze_http_methods(methods):
    """
    Analyze allowed HTTP methods and report their associated security risks.
    """
    if not methods:
        return [{
            "Header": "HTTP Methods",
            "Status": "Unknown",
            "Severity": "Medium",
            "Recommendation": "Server did not respond with an Allow header. Test manually using OPTIONS request."
        }]

    # Known risky HTTP methods and their security risks
    method_risks = {
        "PUT": "Can allow attackers to upload or overwrite files on the server.",
        "DELETE": "Can allow attackers to delete resources or content on the server.",
        "TRACE": "Can be used in cross-site tracing (XST) attacks to steal authentication data.",
        "CONNECT": "Can enable tunneling to internal network resources.",
        "PATCH": "Can modify data on the server if not properly controlled.",
    }

    findings = []
    risky_methods = [m for m in methods if m.upper() in method_risks]

    if risky_methods:
        for method in risky_methods:
            findings.append({
                "Header": f"HTTP Method: {method}",
                "Status": "Unsafe",
                "Severity": "High",
                "Recommendation": f"Disable or restrict '{method}' — {method_risks[method.upper()]}"
            })
    else:
        findings.append({
            "Header": "HTTP Methods",
            "Status": "Safe",
            "Severity": "Low",
            "Recommendation": "No unsafe HTTP methods detected. Common safe methods are GET, POST, HEAD, OPTIONS."
        })

    return findings

def print_http_method_findings(findings, methods):
    """
    Display HTTP method security analysis results with allowed methods and unsafe summary.
    """
    print("\n" + Fore.CYAN + "🔒 HTTP Method Security Check" + Style.RESET_ALL)
    print("====================================")

    # Show allowed methods first
    if methods:
        print(Fore.YELLOW + f"Allowed Methods: {', '.join(methods)}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "Allowed Methods: (None or not advertised)" + Style.RESET_ALL)

    unsafe_findings = [f for f in findings if f["Status"].lower() == "unsafe"]
    print(Fore.WHITE + f"Detected Unsafe Methods: {Fore.RED}{len(unsafe_findings)}{Style.RESET_ALL}\n")

    if not unsafe_findings:
        print(Fore.GREEN + "✅ No unsafe HTTP methods detected.\n" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "──────────────────────────────" + Style.RESET_ALL)
        for i, f in enumerate(unsafe_findings, 1):
            severity_color = {
                "High": Fore.RED,
                "Medium": Fore.YELLOW,
                "Low": Fore.GREEN
            }.get(f["Severity"], Fore.WHITE)

            print(f"{Fore.WHITE}{i}. {f['Header']} — {f['Status']}")
            print(f"   {severity_color}Severity: {f['Severity']}")
            print(f"{Fore.CYAN}   Recommendation: {f['Recommendation']}\n")

        # Print safe methods note
        print(Fore.GREEN + "✅ Safe methods (GET, POST, HEAD, OPTIONS) are acceptable for normal web applications.\n" + Style.RESET_ALL)


# main.py

#from get_header import get_request, parse_headers, print_headers, get_allowed_methods
#from analyze_header import analyze_security_headers, print_findings
from colorama import Fore

url = input("Enter an URL to test your header: ").strip()

# Send GET request
response = get_request(url)

# Parse headers
headers = parse_headers(response)
if not headers:
    print(Fore.RED + "\n[!] Failed to retrieve headers or empty response.\n")
else:
    # Analyze security headers
    findings = analyze_security_headers(headers)
    print_findings(findings)

# Check allowed methods
methods = get_allowed_methods(url)

# Analyze unsafe HTTP methods
method_findings = analyze_http_methods(methods)

# Print all under one clear section
print_http_method_findings(method_findings, methods)


# Ask if user wants to see raw headers
raw_header = input("\nSee raw headers? (y/n): ").strip().lower()
if raw_header == 'y':
    print_headers(headers)