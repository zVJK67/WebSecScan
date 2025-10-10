
# cookie_checker.py 1
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

#no need copy
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

url=input("Enter an URL to test your header: ").strip()
resp = get_request(url)
cookie_findings = analyze_cookies_from_response(resp, url)
print_cookie_findings(cookie_findings)


'''2
import requests
from colorama import Fore, Style

def analyze_cookies(url):
    """
    Analyze cookies set by the server and check for Secure, HttpOnly, and SameSite flags.
    """
    print(Fore.CYAN + "\n🍪 Cookie Security Analysis")
    print("=" * 36)

    try:
        response = requests.get(url, timeout=10)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] Failed to fetch cookies: {e}")
        return

    cookies = response.cookies
    set_cookie_header = response.headers.get("Set-Cookie", "")

    if not cookies and not set_cookie_header:
        print(Fore.YELLOW + "\nNo cookies were set by the server.")
        print(Fore.WHITE + "(Note: This scan checks only cookies set by the server. "
                           "Client-side JavaScript cookies are not detected.)\n")
        return

    # Parse each cookie from Set-Cookie header (in case multiple cookies exist)
    set_cookie_lines = set_cookie_header.split(",") if set_cookie_header else []
    issues = []
    cookie_count = 0

    for cookie_str in set_cookie_lines:
        cookie_str = cookie_str.strip()
        if "=" not in cookie_str:
            continue
        cookie_count += 1
        name = cookie_str.split("=", 1)[0].strip()

        print(Fore.GREEN + f"\n🍪 Cookie Detected: {name}")
        print(Fore.WHITE + f"Raw: {cookie_str}")

        # Flag checks
        missing_flags = []
        if "Secure" not in cookie_str:
            missing_flags.append("Secure")
        if "HttpOnly" not in cookie_str:
            missing_flags.append("HttpOnly")
        if "SameSite" not in cookie_str:
            missing_flags.append("SameSite")

        if missing_flags:
            issues.append({
                "Cookie": name,
                "MissingFlags": missing_flags
            })
            print(Fore.RED + f"⚠️ Missing Flags: {', '.join(missing_flags)}")
        else:
            print(Fore.GREEN + "✅ All recommended flags are set (Secure, HttpOnly, SameSite).")

    if issues:
        print(Fore.YELLOW + "\nSummary of Cookie Issues:")
        print(Fore.WHITE + "──────────────────────────────")
        print(Fore.RED + f"Total Cookies with Missing Flags: {len(issues)}")
        for i, issue in enumerate(issues, start=1):
            print(Fore.RED + f"{i}. {issue['Cookie']}: Missing {', '.join(issue['MissingFlags'])}")
    else:
        print(Fore.GREEN + "\nAll detected cookies include Secure, HttpOnly, and SameSite flags.")

    print(Fore.WHITE + "\n(Note: This scan checks only cookies set by the server. "
                       "Client-side JavaScript cookies are not detected.)\n" + Style.RESET_ALL)
    

test_url = input("Enter an URL to test your header: ").strip()
analyze_cookies(test_url)
'''