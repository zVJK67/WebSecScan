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
# cookie_checker.py
import re
from http.cookies import SimpleCookie
from urllib.parse import urlparse
from colorama import Fore, Style

# Helper: split Set-Cookie header safely if requests collapsed them into one string.
# We try to obtain multiple Set-Cookie entries from the response first (preferred).
def _extract_set_cookie_headers(response):
    """
    Return a list of Set-Cookie header strings from a requests.Response object.
    Tries several techniques to preserve multiple Set-Cookie lines.
    """
    # Preferred: response.raw (if available) may expose get_all
    try:
        raw = getattr(response, "raw", None)
        if raw and hasattr(raw, "headers") and hasattr(raw.headers, "get_all"):
            cookies = raw.headers.get_all("Set-Cookie") or []
            if cookies:
                return cookies
    except Exception:
        pass

    # Fallback: requests keeps headers in response.headers (case-insensitive dict).
    # If multiple Set-Cookie headers were merged into a single string, we attempt to split
    # using a conservative regex that splits where a new cookie typically starts (<name>=)
    hdr = response.headers.get("Set-Cookie") or response.headers.get("set-cookie")
    if not hdr:
        return []

    # If there is a single cookie, return it directly
    # Otherwise attempt splitting on pattern: <cookie-name>=...; [attributes],<cookie-name2>=
    # But cookies themselves may contain commas (rare), so this is a best-effort fallback.
    parts = []
    # A robust approach: find all occurrences of "<name>=" at start or after comma+space and split there.
    # We'll use regex to locate cookie-name= occurrences and slice.
    matches = list(re.finditer(r'(?:(?<=^)|(?<=, ))([A-Za-z0-9_\-\.]+)=', hdr))
    if len(matches) <= 1:
        return [hdr.strip()]

    # Build cookie strings from match positions
    for i, m in enumerate(matches):
        start = m.start(1)
        end = matches[i+1].start(1) if i+1 < len(matches) else len(hdr)
        cookie_str = hdr[start:end].strip().strip(",")
        parts.append(cookie_str)
    return parts


def _parse_cookie_string(cookie_str):
    """
    Parse one Set-Cookie string into (name, value, attrs_dict)
    Uses SimpleCookie for name/value extraction, then manual parse for attributes.
    """
    cookie = SimpleCookie()
    try:
        cookie.load(cookie_str)
    except Exception:
        # fallback: try to split manually
        pass

    if cookie:
        # take the first key
        name = next(iter(cookie.keys()))
        value = cookie[name].value
    else:
        # fallback parsing
        if "=" in cookie_str:
            name, rest = cookie_str.split("=", 1)
            # value ends at first semicolon if attributes follow
            value = rest.split(";", 1)[0].strip()
            name = name.strip()
        else:
            name = cookie_str.strip()
            value = ""

    # parse attributes
    attrs = {}
    parts = cookie_str.split(";")
    # first part is name=value; skip it
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[p.strip().lower()] = True
    return name, value, attrs


def analyze_cookies_from_response(response, url=None):
    """
    Analyze Set-Cookie headers from a requests.Response object.
    Returns a list of findings in the same dict format used elsewhere.
    Notes:
      - If cookies are set client-side (JS), they won't appear here.
      - Pass `url` (optional) so we can check if the site uses HTTPS for Secure requirement.
    """
    findings = []
    cookies = _extract_set_cookie_headers(response)

    if url:
        parsed = urlparse(url)
        is_https = parsed.scheme.lower() == "https"
    else:
        # if response.url exists, check that
        try:
            is_https = getattr(response, "url", "").lower().startswith("https")
        except Exception:
            is_https = False

    if not cookies:
        findings.append({
            "Header": "Set-Cookie",
            "Status": "Missing",
            "Severity": "Medium",
            "Recommendation": "No Set-Cookie headers found in the server response. Client-side cookies may still exist (JS)."
        })
        return findings

    # Evaluate each cookie string
    for cookie_str in cookies:
        name, value, attrs = _parse_cookie_string(cookie_str)
        # normalize keys lower-case for checks
        attrs_lc = {k.lower(): v for k, v in attrs.items()}

        # Basic info item
        findings.append({
            "Header": f"Cookie: {name}",
            "Status": "Present",
            "Severity": "Low",
            "Recommendation": f"Cookie '{name}' is present. Review flags below."
        })

        # Check HttpOnly
        if "httponly" not in attrs_lc:
            findings.append({
                "Header": f"Cookie: {name} - HttpOnly",
                "Status": "Missing",
                "Severity": "High",
                "Recommendation": "Mark cookie with HttpOnly to mitigate access from JavaScript (reduce XSS impact)."
            })

        # Check Secure
        if "secure" not in attrs_lc:
            # if site is HTTPS, this is High
            findings.append({
                "Header": f"Cookie: {name} - Secure",
                "Status": "Missing",
                "Severity": "High" if is_https else "Medium",
                "Recommendation": "Set Secure flag so the cookie is only sent over HTTPS. Required when using SameSite=None."
            })

        # Check SameSite attribute
        samesite = attrs_lc.get("samesite")
        if samesite is None:
            findings.append({
                "Header": f"Cookie: {name} - SameSite",
                "Status": "Missing",
                "Severity": "Medium",
                "Recommendation": "Add SameSite=Lax or Strict to mitigate CSRF; if using SameSite=None, ensure Secure is set."
            })
        else:
            ssv = str(samesite).lower()
            if ssv not in ("lax", "strict", "none"):
                findings.append({
                    "Header": f"Cookie: {name} - SameSite",
                    "Status": f"Invalid ({samesite})",
                    "Severity": "Medium",
                    "Recommendation": "Use SameSite=Lax or SameSite=Strict (or SameSite=None with Secure)."
                })
            elif ssv == "none" and "secure" not in attrs_lc:
                findings.append({
                    "Header": f"Cookie: {name} - SameSite=None without Secure",
                    "Status": "Misconfigured",
                    "Severity": "High",
                    "Recommendation": "SameSite=None requires Secure; add Secure and ensure HTTPS is used."
                })

        # Check expiration (Max-Age or Expires)
        if "max-age" in attrs_lc:
            try:
                ma = int(attrs_lc["max-age"])
                # if very long (> 1 year), flag as informational
                if ma > 365 * 24 * 3600:
                    findings.append({
                        "Header": f"Cookie: {name} - Max-Age",
                        "Status": f"Long ({ma}s)",
                        "Severity": "Low",
                        "Recommendation": "Consider reducing cookie lifetime where possible to limit exposure."
                    })
            except Exception:
                findings.append({
                    "Header": f"Cookie: {name} - Max-Age",
                    "Status": f"Invalid ({attrs_lc['max-age']})",
                    "Severity": "Low",
                    "Recommendation": "Max-Age value is not numeric; verify cookie configuration."
                })
        elif "expires" in attrs_lc:
            findings.append({
                "Header": f"Cookie: {name} - Expires",
                "Status": f"Persistent ({attrs_lc['expires']})",
                "Severity": "Low",
                "Recommendation": "Cookie has Expires attribute (persistent). Consider session cookies when appropriate."
            })
        else:
            findings.append({
                "Header": f"Cookie: {name} - Lifetime",
                "Status": "Session",
                "Severity": "Low",
                "Recommendation": "Cookie is a session cookie (no Expires or Max-Age). Ensure session handling is acceptable."
            })

        # Domain attribute check (informational)
        if "domain" in attrs_lc:
            dom = attrs_lc["domain"]
            if dom.startswith("."):
                findings.append({
                    "Header": f"Cookie: {name} - Domain",
                    "Status": f"Broad ({dom})",
                    "Severity": "Low",
                    "Recommendation": "Cookie domain is broad (leading dot). Ensure domain scoping is intentional."
                })
            else:
                findings.append({
                    "Header": f"Cookie: {name} - Domain",
                    "Status": f"Set ({dom})",
                    "Severity": "Low",
                    "Recommendation": "Domain set; verify this matches the intended scope."
                })

        # Path attribute (informational)
        if "path" in attrs_lc:
            findings.append({
                "Header": f"Cookie: {name} - Path",
                "Status": f"Set ({attrs_lc['path']})",
                "Severity": "Low",
                "Recommendation": "Cookie Path set; ensure it is scoped as narrowly as practical."
            })

    return findings


def print_cookie_findings(findings):
    """
    Pretty-print cookie findings grouped by cookie.
    """
    if not findings:
        print(Fore.GREEN + "\n✅ No cookie-related issues found (no Set-Cookie headers)." + Style.RESET_ALL)
        return

    print("\n" + Fore.CYAN + "🔑 Cookie Security Analysis" + Style.RESET_ALL)
    print(Fore.CYAN + "────────────────────────────────────────────────────────" + Style.RESET_ALL)

    # Group findings by cookie prefix (everything before the first " - " if present)
    grouped = {}
    for f in findings:
        header = f["Header"]
        group = header.split(" - ", 1)[0]  # e.g., "Cookie: sessionid"
        grouped.setdefault(group, []).append(f)

    for group_name, items in grouped.items():
        print(Fore.WHITE + f"\n{group_name}" + Style.RESET_ALL)
        print(Fore.WHITE + "────────────────────────" + Style.RESET_ALL)
        for f in items:
            sev_color = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.GREEN}.get(f["Severity"], Fore.WHITE)
            print(f"{sev_color}{f['Status']}{Style.RESET_ALL} - {f['Recommendation']}")
        print()  # extra newline per cookie

    print(Fore.CYAN + "────────────────────────────────────────────────────────" + Style.RESET_ALL)


# main.py

from get_header import get_request, parse_headers, print_headers, print_options_response, get_allowed_methods
from analyze_header import analyze_security_headers, print_findings, analyze_http_methods, print_http_method_findings
from cookie_checker import analyze_cookies
from findings_summary import print_summary
from colorama import Fore, Style

# === Step 0: Ask for URL ===
url = input(Fore.WHITE + "Enter an URL to test your header: " + Style.RESET_ALL).strip()

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

# === Step 4: Combined Summary ===
print(Fore.GREEN + "\n[4/4] All security misconfiguration checks completed!" + Style.RESET_ALL)
print_summary(findings, method_findings, cookie_findings)


#https://httpbin.org/cookies/set?testcookie=value123