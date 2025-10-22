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

def print_options_response(url):
    """
    Sends an OPTIONS request and displays the full response like 'curl -i -X OPTIONS'.
    """
    print(f"\n{url} — OPTIONS Response:\n" + "=" * 50)
    try:
        response = requests.options(url, timeout=10)
        print(f"HTTP/{response.raw.version // 10}.{response.raw.version % 10} {response.status_code} {response.reason}")
        for k, v in response.headers.items():
            print(f"{k}: {v}")
        print()  # newline spacing
        return response
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch OPTIONS response: {e}")
        return None


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
    hsts = headers.get("Strict-Transport-Security")
    if not hsts:
        findings.append({
            "Header": "Strict-Transport-Security",
            "Status": "Missing",
            "Severity": "High",
            "Recommendation": "Enable HSTS (Strict-Transport-Security) to enforce HTTPS and prevent downgrade attacks."
        })
    else:
        if "max-age" not in hsts.lower():
            findings.append({
                "Header": "Strict-Transport-Security",
                "Status": "Misconfigured",
                "Severity": "Medium",
                "Recommendation": "Add 'max-age' directive (e.g., max-age=31536000) to HSTS for proper enforcement."
            })

    # --- X-Frame-Options ---
    xfo = headers.get("X-Frame-Options")
    if not xfo:
        findings.append({
            "Header": "X-Frame-Options",
            "Status": "Missing",
            "Severity": "Medium",
            "Recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN to protect against clickjacking."
        })
    else:
        if xfo.strip().upper() not in ["DENY", "SAMEORIGIN"]:
            findings.append({
                "Header": "X-Frame-Options",
                "Status": "Misconfigured",
                "Severity": "Medium",
                "Recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN for better clickjacking protection."
            })

    # --- X-XSS-Protection ---
    xxp = headers.get("X-XSS-Protection")
    if not xxp:
        findings.append({
            "Header": "X-XSS-Protection",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Add X-XSS-Protection: 1; mode=block for legacy browser XSS mitigation."
        })
    else:
        if xxp.strip() != "1; mode=block":
            findings.append({
                "Header": "X-XSS-Protection",
                "Status": "Misconfigured",
                "Severity": "Low",
                "Recommendation": "Set X-XSS-Protection: 1; mode=block for older browsers."
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
                "Recommendation": "Ensure X-Content-Type-Options is set to 'nosniff'."
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
        allowed_policies = [
            "no-referrer", "strict-origin", "strict-origin-when-cross-origin", 
            "same-origin", "no-referrer-when-downgrade"
        ]
        if rp.strip().lower() not in allowed_policies:
            findings.append({
                "Header": "Referrer-Policy",
                "Status": "Misconfigured",
                "Severity": "Low",
                "Recommendation": "Use a secure Referrer-Policy such as 'strict-origin-when-cross-origin'."
            })

    # --- Permissions Policy ---
    pp = headers.get("Permissions-Policy")
    if not pp:
        findings.append({
            "Header": "Permissions-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Add Permissions-Policy to control access to features like camera, microphone, or geolocation."
        })

    # --- Cross-Origin Embedder/Opener/Resource Policies (COEP/COOP/CORP) ---
    for policy in ["Cross-Origin-Embedder-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy"]:
        if policy not in headers:
            findings.append({
                "Header": policy,
                "Status": "Missing",
                "Severity": "Low",
                "Recommendation": f"Add {policy} header to improve cross-origin isolation and resource protection."
            })

    # --- Server Information Disclosure ---
    if "Server" in headers:
        findings.append({
            "Header": "Server",
            "Status": "Misconfigured",
            "Severity": "Medium",
            "Recommendation": "Avoid exposing the Server header to reduce fingerprinting and information disclosure."
        })

    # --- Allow Header Disclosure ---
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

    # Top framing
    print("\n" + Fore.MAGENTA + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    print(Fore.CYAN + "🛡️ Security Header Analysis Results" + Style.RESET_ALL)
    print("════════════════════════════════════════════════════════════════")
    print(Fore.WHITE + f"Total Issues Detected: {Fore.YELLOW}{total_issues}{Style.RESET_ALL}")
    print(Fore.WHITE + f"Missing Headers: {Fore.RED}{len(missing)}{Style.RESET_ALL} | Misconfigured: {Fore.YELLOW}{len(misconfigured)}\n")

    def print_group(title, items, color):
        if not items:
            return
        print(color + f"{title}:" + Style.RESET_ALL)
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

    # Print groups
    print_group("🚫 Missing Headers", missing, Fore.RED)
    print_group("⚠️ Misconfigured Headers", misconfigured, Fore.YELLOW)

    if not missing and not misconfigured:
        print(Fore.GREEN + "\n✅ All security headers are properly configured!\n" + Style.RESET_ALL)

    # bottom framing
    print(Fore.MAGENTA + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

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
    print(Fore.CYAN + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

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

            # print method title without repeating "HTTP Method:"
            header_title = f['Header'].replace("HTTP Method: ", "")
            print(f"{Fore.WHITE}{i}. {header_title} — {f['Status']}")
            print(f"   {severity_color}Severity: {f['Severity']}")
            print(f"{Fore.CYAN}   Recommendation: {f['Recommendation']}\n")

        # Print safe methods note
        print(Fore.GREEN + "✅ Safe methods (GET, POST, HEAD, OPTIONS) are acceptable for normal web applications.\n" + Style.RESET_ALL)

    # bottom divider
    print(Fore.CYAN + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

def print_summary(header_findings, method_findings):
    """
    Print a compact summary table with counts by severity and an overall risk level.
    """
    all_findings = list(header_findings) + list(method_findings)

    # counts by severity
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in all_findings:
        sev = f.get("Severity")
        if sev in counts:
            counts[sev] += 1

    total = sum(counts.values())

    # overall risk: HIGH if any High, MEDIUM if no High but >=2 Medium, else LOW
    if counts["High"] > 0:
        overall = "HIGH"
    elif counts["Medium"] >= 2:
        overall = "MEDIUM"
    else:
        overall = "LOW"

    # print table
    print("\n" + Fore.MAGENTA + "==================== Summary ====================" + Style.RESET_ALL)
    print(Fore.WHITE + f"Total Issues: {Fore.YELLOW}{total}{Style.RESET_ALL}")
    print(Fore.RED + f"High Severity: {counts['High']}" + Style.RESET_ALL + " | " +
          Fore.YELLOW + f"Medium: {counts['Medium']}" + Style.RESET_ALL + " | " +
          Fore.GREEN + f"Low: {counts['Low']}" + Style.RESET_ALL)
    print(Fore.WHITE + f"Overall Risk: " + (Fore.RED if overall == "HIGH" else (Fore.YELLOW if overall == "MEDIUM" else Fore.GREEN)) + f"{overall}" + Style.RESET_ALL)
    print(Fore.MAGENTA + "=================================================" + Style.RESET_ALL)


# cookie_checker.py
import requests
from http.cookies import SimpleCookie
from colorama import Fore, Style
from tabulate import tabulate
import json
from datetime import datetime

# Optional: Selenium imports (only needed if user chooses to scan JS cookies)
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def analyze_cookies(url, include_js_cookies=False):
    """
    Analyze cookies set by the server and optionally capture JS-created cookies using Selenium.
    Generates a table report and saves results to a JSON file.
    """
    print(Fore.CYAN + "\n🍪 Cookie Security Analysis")
    print("=" * 36)

    all_cookies = []

    # === 1. Fetch cookies from HTTP response ===
    try:
        response = requests.get(url, timeout=10)
        set_cookie_header = response.headers.get("Set-Cookie", "")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] Failed to fetch cookies: {e}" + Style.RESET_ALL)
        return

    # Parse cookies safely using SimpleCookie
    if set_cookie_header:
        cookie_parser = SimpleCookie()
        cookie_parser.load(set_cookie_header)

        print(Fore.GREEN + "\n[+] Server-side cookies detected:")
        for name, morsel in cookie_parser.items():
            cookie_data = {
                "Name": name,
                "Value": morsel.value,
                "Domain": morsel["domain"] or "N/A",
                "Path": morsel["path"] or "N/A",
                "Secure": "Secure" in morsel.output(),
                "HttpOnly": "HttpOnly" in morsel.output(),
                "SameSite": morsel["samesite"] or "N/A"
            }
            all_cookies.append(cookie_data)

    else:
        print(Fore.YELLOW + "\n[!] No cookies found in server response." + Style.RESET_ALL)

    # === 2. Optionally fetch client-side JS cookies using Selenium ===
    if include_js_cookies:
        print(Fore.CYAN + "\n🌐 Capturing client-side (JavaScript) cookies via Selenium...")
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        js_cookies = driver.get_cookies()
        driver.quit()

        for c in js_cookies:
            cookie_data = {
                "Name": c.get("name"),
                "Value": c.get("value"),
                "Domain": c.get("domain"),
                "Path": c.get("path"),
                "Secure": c.get("secure"),
                "HttpOnly": c.get("httpOnly"),
                "SameSite": c.get("sameSite") or "N/A"
            }
            all_cookies.append(cookie_data)

        print(Fore.GREEN + f"[+] {len(js_cookies)} JavaScript cookies captured." + Style.RESET_ALL)

    # === 3. Analyze cookie flags ===
    issues = []
    for cookie in all_cookies:
        missing = []
        if not cookie["Secure"]:
            missing.append("Secure")
        if not cookie["HttpOnly"]:
            missing.append("HttpOnly")
        if cookie["SameSite"] == "N/A":
            missing.append("SameSite")

        if missing:
            cookie["MissingFlags"] = ", ".join(missing)
            issues.append(cookie)
        else:
            cookie["MissingFlags"] = "None"

    # === 4. Print formatted table report ===
    if all_cookies:
        print(Fore.WHITE + "\n📋 Cookie Report:")
        headers = ["Name", "Domain", "Secure", "HttpOnly", "SameSite", "MissingFlags"]
        table = [[
            c["Name"],
            c["Domain"],
            "✅" if c["Secure"] else "❌",
            "✅" if c["HttpOnly"] else "❌",
            c["SameSite"],
            c["MissingFlags"]
        ] for c in all_cookies]
        print(tabulate(table, headers=headers, tablefmt="grid"))

    else:
        print(Fore.YELLOW + "\nNo cookies detected for analysis." + Style.RESET_ALL)

    # === 5. Save report to JSON ===
    '''
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"cookie_report_{timestamp}.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(all_cookies, f, indent=4)

    print(Fore.GREEN + f"\n✅ Analysis complete. Report saved as: {report_file}" + Style.RESET_ALL)
    print(Fore.WHITE + "\n(Note: JS cookie capture requires Chrome WebDriver installed.)" + Style.RESET_ALL)
    

# === Main execution ===
if __name__ == "__main__":
    test_url = input("Enter a URL to analyze cookies: ").strip()
    js_option = input("Include JS cookies with Selenium? (y/n): ").strip().lower()
    include_js = js_option == "y"
    analyze_cookies(test_url, include_js)
    '''
    # === 6. Return issue summary for main program ===
    cookie_findings = []
    for c in issues:
        sev = "High" if "Secure" in c["MissingFlags"] else ("Medium" if "HttpOnly" in c["MissingFlags"] else "Low")
        cookie_findings.append({
            "Category": "Cookie",
            "Name": c["Name"],
            "Severity": sev,
            "Description": f"Missing flags: {c['MissingFlags']}"
        })

    return cookie_findings


#CORS
import requests
from colorama import Fore, Style

def analyze_cors(url):
    """
    Enhanced CORS analysis with early short-circuit for wildcard+credentials,
    plus optional preflight and reflection checks for deeper analysis.
    """
    print(Fore.CYAN + "\n🌍 CORS Security Analysis")
    print("=" * 36)

    fake_origin = "https://evil-attacker.com"
    findings = []

    try:
        # 1) simple GET with Origin
        resp = requests.get(url, headers={"Origin": fake_origin}, timeout=10)
        # 2) preflight OPTIONS (may reveal Access-Control-Allow-Methods)
        preflight_resp = requests.options(url, headers={
            "Origin": fake_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Test-Header"
        }, timeout=10)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] Failed to check CORS: {e}" + Style.RESET_ALL)
        return findings

    # prefer preflight headers for methods info, but keep GET headers too
    combined = {**resp.headers, **preflight_resp.headers}
    allow_origin = combined.get("Access-Control-Allow-Origin", "")
    allow_credentials = combined.get("Access-Control-Allow-Credentials", "")
    allow_methods = combined.get("Access-Control-Allow-Methods", "")
    vary = combined.get("Vary", "")

    print(Fore.WHITE + "\n📋 CORS Response Headers:")
    print("-" * 36)
    print(f"Access-Control-Allow-Origin: {allow_origin or 'N/A'}")
    print(f"Access-Control-Allow-Credentials: {allow_credentials or 'N/A'}")
    print(f"Access-Control-Allow-Methods: {allow_methods or 'N/A'}")
    print(f"Vary: {vary or 'N/A'}")
    print("-" * 36)

    # --- Immediate critical check: wildcard + credentials (forbidden)
    if allow_origin == "*" and allow_credentials and allow_credentials.lower() == "true":
        findings.append({
            "Category": "CORS",
            "Description": "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true — invalid and critical.",
            "Severity": "High",
            "Recommendation": "Do not use '*' with credentials. Restrict Access-Control-Allow-Origin to a specific trusted origin(s) and return that origin explicitly."
        })
        print(Fore.RED + "[CRITICAL] Wildcard origin with credentials allowed!" + Style.RESET_ALL)
        # still continue to collect context (Vary, methods), but we already flagged critical
    else:
        # --- Wildcard without credentials: medium
        if allow_origin == "*" and not (allow_credentials and allow_credentials.lower() == "true"):
            findings.append({
                "Category": "CORS",
                "Description": "Access-Control-Allow-Origin is '*' — allows any origin.",
                "Severity": "Medium",
                "Recommendation": "Avoid wildcard origins. Use a strict whitelist of trusted origins."
            })
            print(Fore.YELLOW + "[!] Wildcard origin detected ('*')." + Style.RESET_ALL)

        # --- If allow_origin present and not '*' — check reflection / whitelisting
        elif allow_origin:
            # If the server returned the fake_origin value, it's reflection (bad)
            if fake_origin in allow_origin:
                findings.append({
                    "Category": "CORS",
                    "Description": f"Server reflected attacker-controlled Origin ({fake_origin}) — possible CORS bypass.",
                    "Severity": "High",
                    "Recommendation": "Do not reflect Origin header. Implement strict server-side origin whitelist checks using absolute comparisons."
                })
                print(Fore.RED + "[!] Server reflected attacker-controlled Origin. Potential CORS bypass." + Style.RESET_ALL)
            else:
                print(Fore.GREEN + "[+] Access-Control-Allow-Origin is not wildcard and does not reflect attacker origin." + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "[!] No Access-Control-Allow-Origin header found." + Style.RESET_ALL)
            findings.append({
                "Category": "CORS",
                "Description": "No Access-Control-Allow-Origin header present.",
                "Severity": "Low",
                "Recommendation": "If cross-origin access is needed, configure Access-Control-Allow-Origin to only trusted origins."
            })

    # --- Missing Vary: Origin check (when dynamic specific origins are returned)
    if allow_origin and "*" not in allow_origin:
        if "origin" not in vary.lower():
            findings.append({
                "Category": "CORS",
                "Description": "Missing 'Vary: Origin' header while returning specific Access-Control-Allow-Origin values.",
                "Severity": "Medium",
                "Recommendation": "Add 'Vary: Origin' to avoid caching responses across different origins."
            })
            print(Fore.YELLOW + "[!] Missing 'Vary: Origin' — caching issues possible." + Style.RESET_ALL)

    # --- Methods exposure check (from preflight)
    if allow_methods:
        unsafe = {"PUT", "DELETE", "PATCH"}
        methods_set = {m.strip().upper() for m in allow_methods.split(",")}
        exposed = methods_set.intersection(unsafe)
        if exposed:
            findings.append({
                "Category": "CORS",
                "Description": f"Unsafe HTTP methods exposed via CORS: {', '.join(sorted(exposed))}",
                "Severity": "Medium",
                "Recommendation": "Avoid exposing unsafe methods to cross-origin requests or ensure they require proper authentication."
            })
            print(Fore.YELLOW + f"[!] Unsafe methods exposed via CORS: {', '.join(sorted(exposed))}" + Style.RESET_ALL)

    print(Fore.GREEN + "\n✅ CORS analysis completed.\n" + Style.RESET_ALL)
    return findings


#findings_summary.py
from colorama import Fore, Style

def print_summary(header_findings, method_findings, cookie_findings):
    """
    Print a compact summary table with counts by severity and an overall risk level.
    Includes header, method, and cookie analysis findings.
    """
    all_findings = list(header_findings) + list(method_findings) + list(cookie_findings)

    # Counts by severity
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in all_findings:
        sev = f.get("Severity")
        if sev in counts:
            counts[sev] += 1

    total = sum(counts.values())

    # Overall risk: HIGH if any High, MEDIUM if no High but >=2 Medium, else LOW
    if counts["High"] > 0:
        overall = "HIGH"
    elif counts["Medium"] >= 2:
        overall = "MEDIUM"
    else:
        overall = "LOW"

    # Print table
    print("\n" + Fore.MAGENTA + "==================== Summary ====================" + Style.RESET_ALL)
    print(Fore.WHITE + f"Total Issues: {Fore.YELLOW}{total}{Style.RESET_ALL}")
    print(Fore.RED + f"High Severity: {counts['High']}" + Style.RESET_ALL + " | " +
          Fore.YELLOW + f"Medium: {counts['Medium']}" + Style.RESET_ALL + " | " +
          Fore.GREEN + f"Low: {counts['Low']}" + Style.RESET_ALL)
    print(Fore.WHITE + "Overall Risk: " + (
        Fore.RED if overall == "HIGH" else
        (Fore.YELLOW if overall == "MEDIUM" else Fore.GREEN)
    ) + f"{overall}" + Style.RESET_ALL)
    print(Fore.MAGENTA + "=================================================" + Style.RESET_ALL)


# main.py
'''
from get_header import get_request, parse_headers, print_headers, print_options_response, get_allowed_methods
from http_header import analyze_security_headers, print_findings
from http_method import analyze_http_methods, print_http_method_findings
from cookie_checker import analyze_cookies
from cors_checker import analyze_cors
from findings_summary import print_summary
'''
from colorama import Fore, Style

print(Fore.CYAN + "\n=== Web Security Misconfiguration Analyzer ===" + Style.RESET_ALL)

# === Step 0: Ask for URL ===
url = input(Fore.WHITE + "\nEnter an URL to test your header: " + Style.RESET_ALL).strip()

# === Step 1: Header Check ===
print(Fore.CYAN + "\n[1/4] Checking HTTP headers..." + Style.RESET_ALL)

response = get_request(url)
headers = parse_headers(response)
if not headers:
    print(Fore.RED + "\n[!] Failed to retrieve headers or empty response.\n" + Style.RESET_ALL)
    findings = []
else:
    findings = analyze_security_headers(headers)
    print_findings(findings)

raw_header = input("\nSee raw GET headers? (y/n): ").strip().lower()
if raw_header == 'y':
    print_headers(headers)

# === Step 2: HTTP Method Check ===
print(Fore.CYAN + "\n[2/4] Checking HTTP methods..." + Style.RESET_ALL)
methods = get_allowed_methods(url)
method_findings = analyze_http_methods(methods)
print_http_method_findings(method_findings, methods)

options_header = input("\nSee OPTIONS raw response? (y/n): ").strip().lower()
if options_header == 'y':
    print_options_response(url)

# === Step 3: Cookie Security Analysis ===
print(Fore.CYAN + "\n[3/4] Performing Cookie Security Analysis..." + Style.RESET_ALL)
cookie_findings = analyze_cookies(url, include_js_cookies=True)

# === Step 4: CORS Security Analysis ===
print(Fore.CYAN + "\n[4/5] Checking Cross-Origin Resource Sharing (CORS) configuration..." + Style.RESET_ALL)
cors_findings = analyze_cors(url)

# === Step 5: Combined Summary ===
print(Fore.GREEN + "\n[5/5] All security misconfiguration checks completed!" + Style.RESET_ALL)
print_summary(findings, method_findings, cookie_findings + cors_findings)



#https://httpbin.org/cookies/set?testcookie=value123