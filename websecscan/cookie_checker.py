# cookie_checker.py
import re
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

import requests
from http.cookies import SimpleCookie
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from colorama import Fore, Style
from tabulate import tabulate

# --- Helper: session with retries ---
def _get_session(retries: int = 2, backoff: float = 0.2) -> requests.Session:
    s = requests.Session()
    retry = Retry(total=retries, backoff_factor=backoff,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(['GET', 'HEAD', 'OPTIONS']))
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "WebSecScan/1.0"})
    s.verify = False
    return s


# Regex to split combined Set-Cookie header safely.
_SET_COOKIE_SPLIT_RE = re.compile(r',(?=\s*[A-Za-z0-9!#$%&\'*+\-.^_`|~]+=)')

def _extract_set_cookie_headers(response: requests.Response) -> List[str]:
    """
    Return a list of raw Set-Cookie header lines found in the response or any intermediate redirects.
    Handles:
      - responses where .raw.headers.get_all("Set-Cookie") is available
      - combined single Set-Cookie header strings (splits safely)
      - cookies set on redirect responses (response.history)
    """
    headers_list: List[str] = []

    if response is None:
        return []

    # Collect final response and any redirect hops (history may be empty)
    candidates = list(getattr(response, "history", []) or []) + [response]

    for resp in candidates:
        try:
            raw_headers = getattr(resp, "raw", None)
            if raw_headers is not None and hasattr(raw_headers, "headers"):
                get_all = getattr(raw_headers.headers, "get_all", None)
                if callable(get_all):
                    scs = get_all("Set-Cookie")
                    if scs:
                        for sc in scs:
                            if sc and sc.strip():
                                headers_list.append(sc.strip())
                        continue
        except Exception:
            pass

        # Fallback: look at resp.headers (CaseInsensitiveDict). May contain a single combined Set-Cookie.
        sc_header = resp.headers.get("Set-Cookie")
        if sc_header:
            # Split safely on commas that start a cookie (regex handles attributes containing commas)
            parts = _SET_COOKIE_SPLIT_RE.split(sc_header)
            for p in parts:
                p = p.strip()
                if p:
                    headers_list.append(p)

    # Deduplicate while preserving order (some servers may repeat same Set-Cookie in multiple hops)
    seen = set()
    out = []
    for h in headers_list:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out

def _parse_set_cookie_header(raw_sc: str) -> Dict[str, Any]:

    result: Dict[str, Any] = {
        "Name": None,
        "Value": None,
        "Domain": "N/A",
        "Path": "N/A",
        "Secure": False,
        "HttpOnly": False,
        "SameSite": "N/A",
        "Expires": "N/A",
        "MaxAge": "N/A",
        "Raw": raw_sc
    }

    c = SimpleCookie()
    try:
        c.load(raw_sc)
    except Exception:
        m = re.match(r'^\s*([^=;\s]+)=([^;]+)', raw_sc)
        if m:
            result["Name"] = m.group(1)
            result["Value"] = m.group(2)
    else:
        if c:
            cookie_key = next(iter(c.keys()))
            morsel = c[cookie_key]
            result["Name"] = cookie_key
            result["Value"] = morsel.value

    attr_re = re.compile(r'(?i)(?:;\s*|^)(?P<attr>Secure|HttpOnly|SameSite|Domain|Path|Expires|Max-Age)(?:=(?P<val>[^;]+))?')
    for m in attr_re.finditer(raw_sc):
        attr = m.group("attr").lower()
        val = m.group("val")
        if attr == "secure":
            result["Secure"] = True
        elif attr == "httponly":
            result["HttpOnly"] = True
        elif attr == "samesite":
            result["SameSite"] = val.strip() if val else "None"
        elif attr == "domain" and val:
            result["Domain"] = val.strip()
        elif attr == "path" and val:
            result["Path"] = val.strip()
        elif attr == "expires" and val:
            result["Expires"] = val.strip()
        elif attr == "max-age" and val:
            result["MaxAge"] = val.strip()

    return result

def _is_session_like_cookie(name: str, value: str) -> bool:
    """
    Heuristic to detect if a cookie is likely a session cookie.
    """
    session_patterns = [
        r'session',
        r'sess',
        r'token',
        r'auth',
        r'login',
        r'user',
        r'jwt',
        r'access',
        r'csrf'
    ]
    
    name_lower = (name or "").lower()
    for pattern in session_patterns:
        if re.search(pattern, name_lower):
            return True
    
    # Check if value looks like a random token (long alphanumeric string)
    if value and len(value) >= 16 and re.match(r'^[a-zA-Z0-9+/=_-]+$', value):
        return True
    
    return False

def _check_weak_session_id(value: str) -> bool:
    """
    Check if session ID appears weak (too short or predictable).
    Threshold: < 16 bytes (128 bits) is considered weak.
    """
    if not value:
        return False
    if len(value) < 16:
        return True
    
    # Check if only numeric (predictable)
    if value.isdigit():
        return True
    
    # Check for very simple patterns
    if re.match(r'^(.)\1+$', value):  # All same character
        return True
    
    return False

def _parse_expiry_days(expires_str: str, max_age_str: str) -> Optional[int]:

    if max_age_str != "N/A":
        try:
            seconds = int(max_age_str)
            return seconds // 86400  # Convert to days
        except:
            pass
    
    if expires_str != "N/A":
        try:
            # Try to parse common date formats
            from email.utils import parsedate_to_datetime
            expiry_date = parsedate_to_datetime(expires_str)
            now = datetime.now(expiry_date.tzinfo)
            delta = expiry_date - now
            return delta.days
        except:
            pass
    
    return None

def _analyze_cookie_list(cookies: List[Dict[str, Any]], is_server_side: bool = True) -> List[Dict[str, Any]]:
    """
    Analyze a list of cookies and return issues found.
    Enhanced detection logic based on server-side vs client-side context.
    """
    issues = []
    for c in cookies:
        issue_types = []
        
        # Check if this looks like a session/auth cookie
        is_session = _is_session_like_cookie(c.get("Name", ""), c.get("Value", ""))
        
        # HttpOnly check (critical for session cookies)
        if not c.get("HttpOnly"):
            issue_types.append("HttpOnly")
        
        # Secure check
        if not c.get("Secure"):
            issue_types.append("Secure")
        
        # SameSite check
        ss = c.get("SameSite", "N/A")
        if ss in ("N/A", None, ""):
            issue_types.append("SameSite")
        
        # Path check - flag if path is too broad (/ or N/A)
        path = c.get("Path", "N/A")
        if path == "/" or path == "N/A":
            issue_types.append("Path")
        
        # Expires/Max-Age check
        expires = c.get("Expires", "N/A")
        max_age = c.get("MaxAge", "N/A")
        
        if is_server_side:
            # Server-side: Flag if NO expiry is set (session cookies should have explicit lifetime)
            if expires == "N/A" and max_age == "N/A":
                issue_types.append("Expires/Max-Age")
        else:
            # Client-side: Flag if expiry is TOO LONG (> 30 days)
            expiry_days = _parse_expiry_days(expires, max_age)
            if expiry_days is not None and expiry_days > 30:
                issue_types.append("Excessive Lifetime")
        
        # Weak Session ID check (only for session-like cookies)
        if is_session:
            value = c.get("Value", "")
            if _check_weak_session_id(value):
                issue_types.append("Weak Session ID")
        
        # Domain scope check - flag if domain starts with '.' (wildcard subdomain)
        domain = c.get("Domain", "N/A")
        if domain and isinstance(domain, str) and domain.startswith("."):
            issue_types.append("Domain")

        if issue_types:
            issues.append({
                "Name": c.get("Name"),
                "IssueTypes": issue_types,
                "IsSession": is_session
            })
    
    return issues

def _dedupe_issues(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicate issue entries while preserving order.
    Two entries are considered the same if they have same Name and same set of IssueTypes.
    """
    seen = set()
    out: List[Dict[str, Any]] = []
    for it in issues:
        name = it.get("Name")
        types = tuple(sorted(it.get("IssueTypes", [])))
        key = (name, types)
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out

def analyze_cookies(url: str, include_js_cookies: bool = True, verbose: bool = False) -> List[Dict[str, Any]]:

    session = _get_session()
    server_cookies: List[Dict[str, Any]] = []
    client_cookies: List[Dict[str, Any]] = []

    # Fetch cookies from HTTP response 
    try:
        resp = session.get(url, timeout=10)
    except requests.exceptions.SSLError as e:
        print(Fore.YELLOW + f"TLS verification failed while fetching cookies for {url}: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + "   Retrying without certificate verification to continue the scan..." + Style.RESET_ALL)
        try:
            resp = session.get(url, timeout=10, verify=False)
        except requests.RequestException as e2:
            print(Fore.RED + f"[ERROR] Could not fetch cookies from {url}: {e2}" + Style.RESET_ALL)
            return []
    except requests.RequestException as e:
        print(Fore.RED + f"[ERROR] Could not fetch cookies from {url}: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + "   The scanner will continue; no server-side cookies were collected." + Style.RESET_ALL)
        return []

    # Extract Set-Cookie headers (includes redirect hops)
    raw_set_cookies = _extract_set_cookie_headers(resp)
    if raw_set_cookies:
        for raw in raw_set_cookies:
            parsed = _parse_set_cookie_header(raw)
            server_cookies.append(parsed)
    else:
        # Check CookieJar
        jar = resp.cookies
        if jar:
            for cookie in jar:
                parsed = {
                    "Name": cookie.name,
                    "Value": cookie.value,
                    "Domain": cookie.domain or "N/A",
                    "Path": cookie.path or "N/A",
                    "Secure": bool(cookie.secure),
                    "HttpOnly": bool(getattr(cookie, "rest", {}).get("HttpOnly", False)) or False,
                    "SameSite": getattr(cookie, "sameSite", "N/A") or "N/A",
                    "Expires": "N/A",
                    "MaxAge": "N/A",
                    "Raw": None
                }
                server_cookies.append(parsed)

    # Fetch client-side JS cookies using Selenium 
    if include_js_cookies:
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options

            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=chrome_options)
            driver.get(url)
            js_cookies = driver.get_cookies()
            driver.quit()

            for c in js_cookies:
                parsed = {
                    "Name": c.get("name"),
                    "Value": c.get("value"),
                    "Domain": c.get("domain") or "N/A",
                    "Path": c.get("path") or "N/A",
                    "Secure": bool(c.get("secure")),
                    "HttpOnly": bool(c.get("httpOnly")),
                    "SameSite": c.get("sameSite") or "N/A",
                    "Expires": str(c.get("expiry", "N/A")) if c.get("expiry") else "N/A",
                    "MaxAge": "N/A",
                    "Raw": None
                }
                client_cookies.append(parsed)

        except Exception:
            pass

    # Analyze cookies and detect issues 
    server_issues = _analyze_cookie_list(server_cookies, is_server_side=True)
    client_issues = _analyze_cookie_list(client_cookies, is_server_side=False)

    # Deduplicate issues to avoid repeated printing
    server_issues = _dedupe_issues(server_issues)
    client_issues = _dedupe_issues(client_issues)

    # Determine severity based on ALL detected issue types
    all_issue_types = set()
    for issues in [server_issues, client_issues]:
        for cookie_issue in issues:
            all_issue_types.update(cookie_issue.get("IssueTypes", []))

    # If ONLY HttpOnly and/or Secure are missing (nothing else), Low severity
    if all_issue_types and all_issue_types <= {"HttpOnly", "Secure"}:
        severity = "Low"
        cvss = "3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)"
    elif all_issue_types:
        # Any other issue detected = High severity
        severity = "High"
        cvss = "7.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)"
    else:
        severity = "Info"
        cvss = "N/A"

    # Print formatted output 
    print(Fore.CYAN + "\nCookie & Session Security Configuration" + Style.RESET_ALL)
    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    has_findings = bool(server_issues or client_issues)
    if has_findings:
        print(Fore.WHITE + "Risk Rating:" + Style.RESET_ALL)
        print(f"Severity: {severity}")
        print(f"CVSS: {cvss}")

    # [a] Server-Side Cookies
    print(Fore.MAGENTA + "\n[a] Server-Side Cookies" + Style.RESET_ALL)
    print(Fore.YELLOW + "**********************************************************" + Style.RESET_ALL)

    if server_cookies:
        if verbose:
            if raw_set_cookies:
                for raw in raw_set_cookies:
                    print(f"Set-Cookie: {raw}")
            else:
                for c in server_cookies:
                    print(f"Cookie: {c['Name']}={c['Value']}")
    else:
        print("[!] No server-side cookies detected.")
        print(
            Fore.YELLOW +
            "    Cookies may be set only after authentication or specific user actions.\n"
            "    Manual verification is recommended for protected areas."
            + Style.RESET_ALL
        )
        print(Fore.YELLOW + "**********************************************************" + Style.RESET_ALL)
    
    print("\nFindings:")
    print(Fore.CYAN + f"``````````````````````````````````````````````````````````````````````````````````" + Style.RESET_ALL)
    if server_issues:
        _print_issues(server_issues, is_server_side=True)
    elif server_cookies:
        print(Fore.GREEN + "✓ No issues found.\n" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "[!] No server-side cookie issues detected.\n" + Style.RESET_ALL)

    print(Fore.MAGENTA + "~" * 80 + Style.RESET_ALL)

    # [b] Client-Side Cookies
    print(Fore.MAGENTA + "\n[b] Client-Side Cookies" + Style.RESET_ALL)
    print(Fore.YELLOW + "**********************************************************" + Style.RESET_ALL)

    if client_cookies:
        if verbose:
            for c in client_cookies:
                attrs = []
                if c.get("Secure"):
                    attrs.append("Secure")
                if c.get("HttpOnly"):
                    attrs.append("HttpOnly")
                if c.get("SameSite") not in ("N/A", None, ""):
                    attrs.append(f"SameSite={c.get('SameSite')}")
                attrs_str = "; ".join(attrs) if attrs else "(no attributes)"
                print(f"document.cookie: {c.get('Name')}={c.get('Value')}; {attrs_str}")
    else:
        print("[!] No client-side cookies detected.")
        print(
            Fore.YELLOW +
            "    Cookies may be created dynamically via JavaScript after user interaction.\n"
            "    Manual verification is recommended."
            + Style.RESET_ALL
        )
        print(Fore.YELLOW + "**********************************************************" + Style.RESET_ALL)
        

    print("\nFindings:")
    print(Fore.CYAN + f"``````````````````````````````````````````````````````````````````````````````````" + Style.RESET_ALL)
    if client_issues:
        _print_issues(client_issues, is_server_side=False)
    elif client_cookies:
        print(Fore.GREEN + "✓ No issues found.\n" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "[!] No client-side cookies detected.\n" + Style.RESET_ALL)

    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    # Return findings for summary (category-level severity) 
    cookie_findings: List[Dict[str, Any]] = []

    # MAPPING: Display title -> ItemDetails key
    ISSUE_TO_ITEM_KEY = {
        "Missing HttpOnly Attribute": "HttpOnly",
        "Missing Secure Attribute": "Secure",
        "Missing SameSite Attribute": "SameSite",
        "Overly Broad Path Attribute": "Path",
        "Missing Expires / Max-Age Attribute": "Expires/Max-Age",
        "Weak Session ID": "Weak Session ID",
        "Overly Broad Domain Attribute": "Domain",
        "Excessive Cookie Lifetime": "Excessive Lifetime",
    }

    ISSUE_TITLES = {
        "HttpOnly": "Missing HttpOnly Attribute",
        "Secure": "Missing Secure Attribute",
        "SameSite": "Missing SameSite Attribute",
        "Path": "Overly Broad Path Attribute",
        "Expires/Max-Age": "Missing Expires / Max-Age Attribute",
        "Weak Session ID": "Weak Session ID",
        "Domain": "Overly Broad Domain Attribute",
        "Excessive Lifetime": "Excessive Cookie Lifetime",
    }

    # -------- Server-side cookies --------
    for issue in server_issues:
        cookie_name = issue.get("Name")
        cookie = next((c for c in server_cookies if c.get("Name") == cookie_name), None)
        if not cookie:
            continue

        for issue_type in issue.get("IssueTypes", []):
            finding_title = ISSUE_TITLES.get(issue_type, issue_type)
            item_key = ISSUE_TO_ITEM_KEY.get(finding_title, issue_type)

            cookie_findings.append({
                "Category": "Cookie Security (Server-Side)",
                "Scope": "Server-Side",
                "Finding": finding_title,
                "_item_short": item_key,  
                "Evidence": _build_cookie_evidence(issue_type, cookie),
                "Severity": severity,
                "_cookie_name": cookie.get("Name"),
                "_cookie_value": cookie.get("Value"),
                "_cookie_secure": cookie.get("Secure"),
                "_cookie_httponly": cookie.get("HttpOnly"),
                "_cookie_samesite": cookie.get("SameSite"),
                "_cookie_path": cookie.get("Path"),
                "_cookie_domain": cookie.get("Domain"),
                "_cookie_expires": cookie.get("Expires")
            })

    # -------- Client-side cookies --------
    for issue in client_issues:
        cookie_name = issue.get("Name")
        cookie = next((c for c in client_cookies if c.get("Name") == cookie_name), None)
        if not cookie:
            continue

        for issue_type in issue.get("IssueTypes", []):
            finding_title = ISSUE_TITLES.get(issue_type, issue_type)
            item_key = ISSUE_TO_ITEM_KEY.get(finding_title, issue_type)

            cookie_findings.append({
                "Category": "Cookie Security (Client-Side)",
                "Scope": "Client-Side",
                "Finding": finding_title,
                "_item_short": item_key,  
                "Evidence": _build_cookie_evidence(issue_type, cookie),
                "Severity": severity,
                "_cookie_name": cookie.get("Name"),
                "_cookie_value": cookie.get("Value"),
                "_cookie_secure": cookie.get("Secure"),
                "_cookie_httponly": cookie.get("HttpOnly"),
                "_cookie_samesite": cookie.get("SameSite"),
                "_cookie_path": cookie.get("Path"),
                "_cookie_domain": cookie.get("Domain"),
                "_cookie_expires": cookie.get("Expires")
            })

    return cookie_findings

def _print_issues(issues: List[Dict[str, Any]], is_server_side: bool = True):
    """Print detected issues in numbered format."""
    
    # Define issue mappings for server-side
    server_issue_map = {
        "HttpOnly": ("Missing HttpOnly Attribute", 
                     "Set the HttpOnly flag in all session cookies (e.g. `Set-Cookie: sessionid=...; HttpOnly`)."),
        "Secure": ("Missing Secure Attribute", 
                   "Add the Secure flag to ensure cookies are only delivered via HTTPS (e.g. `Set-Cookie: sessionid=...; Secure`)."),
        "SameSite": ("Missing SameSite Attribute", 
                     "Set SameSite=Lax or SameSite=Strict for session cookies to mitigate CSRF attacks."),
        "Path": ("Missing Specific Path Attribute", 
                 "Restrict Path to required endpoints (e.g. `Set-Cookie: sessionid=...; Path=/admin`)."),
        "Expires/Max-Age": ("Missing Expires/Max-Age Attribute", 
                            "Set a Max-Age or Expires attribute with an appropriate session lifetime."),
        "Weak Session ID": ("Weak Session ID", 
                           "Use long, cryptographically secure random session identifiers (>=128 bits, e.g. `sessionid=63b7c9f9f0a56edbcf9f1a31e9e1561c`)."),
        "Domain": ("Cookie Scope Misconfiguration - Domain Attribute", 
                   "Restrict the Domain attribute to the minimal required scope (e.g. `auth.example.com`).")
    }

    # Define issue mappings for client-side
    client_issue_map = {
        "Secure": ("Missing Secure Flag",
                   "Enable the Secure flag so that cookies are only sent over HTTPS."),
        "HttpOnly": ("Missing HttpOnly Attribute",
                     "Mark the cookie as HttpOnly to prevent JavaScript access."),
        "SameSite": ("Missing SameSite Attribute",
                     "Set SameSite=Lax or SameSite=Strict. If using SameSite=None, ensure Secure is also set."),
        "Excessive Lifetime": ("Excessive Cookie Lifetime",
                               "Limit long-term cookies to less than 1 year; session cookies should expire when the browser closes."),
        "Path": ("Overly Broad Path Attribute",
                 "Restrict Path to only required endpoints (e.g., Path=/admin)."),
        "Domain": ("Overly Broad Domain Attribute",
                   "Restrict the Domain attribute to the specific subdomain that requires the cookie."),
        "Weak Session ID": ("Weak Session ID",
                           "Use long, cryptographically secure random session identifiers (>=128 bits).")
    }

    issue_map = server_issue_map if is_server_side else client_issue_map

    # Collect all unique issue types in order they appear
    all_types = []
    for issue in issues:
        for it in issue.get("IssueTypes", []):
            if it not in all_types:
                all_types.append(it)

    for idx, issue_type in enumerate(all_types, 1):
        title, recommendation = issue_map.get(issue_type, (issue_type, "Review cookie configuration."))
        print(f"{idx}. {title}")
        print(f"   Recommendation: {recommendation}\n")


def _build_cookie_evidence(issue_type: str, cookie: dict) -> str:
    name = cookie.get("Name")
    value = cookie.get("Value")

    # Build full attribute string (CLI-equivalent)
    attrs = []

    if cookie.get("SameSite") not in ("N/A", None, ""):
        attrs.append(f"SameSite={cookie.get('SameSite')}")

    if cookie.get("Path") not in ("N/A", None, ""):
        attrs.append(f"Path={cookie.get('Path')}")

    if cookie.get("Domain") not in ("N/A", None, ""):
        attrs.append(f"Domain={cookie.get('Domain')}")

    if cookie.get("Secure"):
        attrs.append("Secure")

    if cookie.get("HttpOnly"):
        attrs.append("HttpOnly")

    attr_str = "; ".join(attrs)

    # Missing flags → MUST show full cookie value
    if issue_type in {"HttpOnly", "Secure", "SameSite"}:
        if cookie.get("Raw"):
            return f"Set-Cookie: {cookie['Raw']}"

        # Client-side cookie reconstruction
        if attr_str:
            return f"document.cookie: {name}={value}; {attr_str}"

        return f"document.cookie: {name}={value}"

    # Attribute-specific evidence
    if issue_type == "Path":
        return f"Path={cookie.get('Path', 'N/A')}"

    if issue_type == "Domain":
        return f"Domain={cookie.get('Domain', 'N/A')}"

    if issue_type in {"Expires/Max-Age", "Excessive Lifetime"}:
        return f"Expires={cookie.get('Expires', 'N/A')}, Max-Age={cookie.get('MaxAge', 'N/A')}"

    if issue_type == "Weak Session ID":
        return f"{name}={value}"

    return f"Cookie: {name}"

