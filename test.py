import requests
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

    return findings


def print_findings(findings):
    missing = [f for f in findings if f["Status"].lower() == "missing"]
    misconfigured = [f for f in findings if f["Status"].lower() == "misconfigured"]

    def print_group(title, items, color):
        if not items:
            return
        print(color + f"\n{title}:")
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

    print(Fore.CYAN + "\n🛡️ Security Header Analysis Results" + Style.RESET_ALL)
    print("====================================")

    print_group("🚫 Missing Headers", missing, Fore.RED)
    print_group("⚠️ Misconfigured Headers", misconfigured, Fore.YELLOW)

    if not missing and not misconfigured:
        print(Fore.GREEN + "\n✅ All security headers are properly configured!\n" + Style.RESET_ALL)



# set of methods we consider "unsafe" in typical security checks
UNSAFE_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

def analyze_http_methods(url, probe=False, timeout=10):
    """
    Check server for allowed/unsafe HTTP methods.
    - By default: send OPTIONS and parse Allow header (non-destructive).
    - probe=True: optionally attempt a TRACE probe (may be blocked or echo).
    Returns a list of findings in same dict format as analyze_security_headers().
    """
    findings = []

    try:
        # Primary, non-destructive check: OPTIONS and Allow header
        resp = requests.options(url, timeout=timeout, allow_redirects=True)
        allow_hdr = resp.headers.get("Allow") or resp.headers.get("allow")

        if not allow_hdr:
            findings.append({
                "Header": "Allow",
                "Status": "Missing",
                "Severity": "Medium",
                "Recommendation": ("No Allow header returned by OPTIONS. "
                                   "If safe, enable server to advertise allowed methods or "
                                   "manually verify with permission. Consider restricting methods "
                                   "to GET, HEAD, OPTIONS, POST where appropriate.")
            })
        else:
            # parse methods from header, normalize
            methods = {m.strip().upper() for m in allow_hdr.split(",") if m.strip()}
            unsafe_present = methods.intersection(UNSAFE_METHODS)
            if unsafe_present:
                findings.append({
                    "Header": "Allow",
                    "Status": f"Unsafe methods allowed: {', '.join(sorted(unsafe_present))}",
                    "Severity": "High" if ("DELETE" in unsafe_present or "PUT" in unsafe_present) else "Medium",
                    "Recommendation": ("Remove or tightly control unsafe methods (PUT, DELETE, PATCH, TRACE, CONNECT). "
                                       "If they are required, restrict access via authentication and IP/network controls.")
                })
            else:
                findings.append({
                    "Header": "Allow",
                    "Status": "Safe",
                    "Severity": "Low",
                    "Recommendation": "Allow header present and does not advertise dangerous methods."
                })

        # Optional probe (use with caution): check TRACE
        if probe:
            # TRACE is commonly considered unsafe because it can reflect payloads
            try:
                trace_resp = requests.request("TRACE", url, timeout=timeout, allow_redirects=True)
                # typical safe response is 405 Method Not Allowed, 501 Not Implemented, or blocked (4xx/5xx)
                if trace_resp.status_code in (200, 201, 203):
                    findings.append({
                        "Header": "TRACE",
                        "Status": f"Allowed (HTTP {trace_resp.status_code})",
                        "Severity": "High",
                        "Recommendation": "Disable TRACE support on the server to prevent cross-site tracing attacks."
                    })
                elif trace_resp.status_code in (405, 501):
                    findings.append({
                        "Header": "TRACE",
                        "Status": "Not allowed",
                        "Severity": "Low",
                        "Recommendation": "TRACE is not allowed (good)."
                    })
                else:
                    # unknown behaviour — flag as medium
                    findings.append({
                        "Header": "TRACE",
                        "Status": f"Unexpected response: {trace_resp.status_code}",
                        "Severity": "Medium",
                        "Recommendation": "Investigate TRACE handling. If TRACE is not required, disable it."
                    })
            except Exception as e:
                findings.append({
                    "Header": "TRACE",
                    "Status": "Probe failed",
                    "Severity": "Low",
                    "Recommendation": f"TRACE probe failed: {e}. Skipping active probe or try with probe=False."
                })

    except requests.RequestException as e:
        findings.append({
            "Header": "HTTP Methods",
            "Status": "Scan failed",
            "Severity": "Medium",
            "Recommendation": f"Could not query OPTIONS for {url}: {e}"
        })

    return findings


# Example of integration: combine header analysis + method checks
def analyze_url(url, headers, probe_methods=False):
    findings = analyze_security_headers(headers)
    findings += analyze_http_methods(url, probe=probe_methods)
    return findings


# main

from get_header import get_request, parse_headers, print_headers
from colorama import Fore

url = input("Enter a URL to test your headers: ").strip()

# Send GET request
response = get_request(url)

# Parse headers
headers = parse_headers(response)
if not headers:
    print(Fore.RED + "\n[!] Failed to retrieve headers or empty response.\n")
else:
    # Analyze security headers
    findings = analyze_security_headers(headers)

    # Analyze HTTP methods together
    findings += analyze_http_methods(url, probe=False)

    # Print findings
    print_findings(findings)

    # Ask if user wants to see raw headers
    raw_header = input("\nSee raw headers? (y/n): ").strip().lower()
    if raw_header == 'y':
        print_headers(headers)

