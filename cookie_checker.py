import re
from typing import List, Dict, Any, Optional
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
    return s

# Regex to split combined Set-Cookie header safely.
# It splits on commas that are followed by optional whitespace and then a token that looks like "Name="
# This avoids splitting cookie attribute values which may contain commas.
_SET_COOKIE_SPLIT_RE = re.compile(r',(?=\s*[A-Za-z0-9!#$%&\'*+\-.^_`|~]+=)')

def _extract_set_cookie_headers(response: requests.Response) -> List[str]:
    """
    Return a list of raw Set-Cookie header lines. Handles:
      - response.raw.headers.get_all('Set-Cookie') if available (best)
      - otherwise, fall back to response.headers.get('Set-Cookie') and split safely via regex
    """
    # 1) Try to use raw headers from urllib3 if available (preserves multiple headers)
    try:
        raw_headers = getattr(response, "raw", None)
        if raw_headers is not None and hasattr(raw_headers, "headers"):
            get_all = getattr(raw_headers.headers, "get_all", None)
            if callable(get_all):
                sc = get_all("Set-Cookie")
                if sc:
                    return list(sc)
    except Exception:
        pass

    # 2) Fallback: use response.headers (may be folded). Safely split using regex.
    sc_header = response.headers.get("Set-Cookie")
    if not sc_header:
        return []

    parts = _SET_COOKIE_SPLIT_RE.split(sc_header)
    return [p.strip() for p in parts if p.strip()]

def _parse_set_cookie_header(raw_sc: str) -> Dict[str, Any]:
    """
    Parse a single Set-Cookie header string into attributes.
    Returns a dict with keys: Name, Value, Domain, Path, Secure (bool), HttpOnly (bool), SameSite
    """
    result: Dict[str, Any] = {
        "Name": None,
        "Value": None,
        "Domain": "N/A",
        "Path": "N/A",
        "Secure": False,
        "HttpOnly": False,
        "SameSite": "N/A",
        "Raw": raw_sc
    }

    # SimpleCookie helps with name/value parsing (it ignores attributes)
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

    # Now manually extract attributes (case-insensitive)
    attr_re = re.compile(r'(?i)(?:;\s*|^)(?P<attr>Secure|HttpOnly|SameSite|Domain|Path)(?:=(?P<val>[^;]+))?')
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

    return result

def analyze_cookies(url: str, include_js_cookies: bool = False) -> List[Dict[str, Any]]:
    """
    Analyze cookies set by the server and optionally capture JS-created cookies using Selenium.
    Returns a summary list (cookie_findings) suitable for integration with the rest of the scanner.
    """
    print(Fore.CYAN + "\n🍪 Cookie Security Analysis" + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 36 + Style.RESET_ALL)

    session = _get_session()
    all_cookies: List[Dict[str, Any]] = []

    # === 1. Fetch cookies from HTTP response ===
    try:
        resp = session.get(url, timeout=10)
    except requests.RequestException as e:
        print(Fore.RED + f"[ERROR] Failed to fetch cookies from {url}: {e}" + Style.RESET_ALL)
        return []

    # Extract Set-Cookie headers robustly (handles multiple headers folded into one)
    raw_set_cookies = _extract_set_cookie_headers(resp)
    if raw_set_cookies:
        print(Fore.GREEN + f"\n[+] Server-side cookies detected: {len(raw_set_cookies)}" + Style.RESET_ALL)
        for raw in raw_set_cookies:
            parsed = _parse_set_cookie_header(raw)
            all_cookies.append(parsed)
    else:
        # Even if no Set-Cookie header, check response.cookies CookieJar for cookies (name/value)
        jar = resp.cookies
        if jar:
            print(Fore.GREEN + f"\n[+] Server-side cookies detected via CookieJar: {len(jar)}" + Style.RESET_ALL)
            for cookie in jar:
                parsed = {
                    "Name": cookie.name,
                    "Value": cookie.value,
                    "Domain": cookie.domain or "N/A",
                    "Path": cookie.path or "N/A",
                    "Secure": bool(cookie.secure),
                    "HttpOnly": bool(getattr(cookie, "rest", {}).get("HttpOnly", False)) or False,
                    "SameSite": getattr(cookie, "sameSite", "N/A") or "N/A",
                    "Raw": None
                }
                all_cookies.append(parsed)
        else:
            print(Fore.YELLOW + "\n[!] No cookies found in server response." + Style.RESET_ALL)

    # === 2. Optionally fetch client-side JS cookies using Selenium ===
    if include_js_cookies:
        print(Fore.CYAN + "\n🌐 Capturing client-side (JavaScript) cookies via Selenium..." + Style.RESET_ALL)
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options

            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--no-sandbox")
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
                    "Raw": None
                }
                all_cookies.append(parsed)

            print(Fore.GREEN + f"[+] {len(js_cookies)} JavaScript cookies captured." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.YELLOW + f"[!] Selenium JS cookie capture skipped: {e}" + Style.RESET_ALL)

    # === 3. Analyze cookie flags ===
    issues: List[Dict[str, Any]] = []
    for c in all_cookies:
        missing = []
        if not c.get("Secure"):
            missing.append("Secure")
        if not c.get("HttpOnly"):
            missing.append("HttpOnly")
        ss = c.get("SameSite", "N/A")
        if ss in ("N/A", None, ""):
            missing.append("SameSite")
        c["MissingFlags"] = ", ".join(missing) if missing else "None"
        if missing:
            issues.append(c)

    # === 4. Print formatted table report ===
    if all_cookies:
        print(Fore.WHITE + "\n📋 Cookie Report:" + Style.RESET_ALL)
        headers = ["Name", "Domain", "Secure", "HttpOnly", "SameSite", "MissingFlags"]
        table = [[
            c.get("Name"),
            c.get("Domain"),
            "✅" if c.get("Secure") else "❌",
            "✅" if c.get("HttpOnly") else "❌",
            c.get("SameSite"),
            c.get("MissingFlags")
        ] for c in all_cookies]
        print(tabulate(table, headers=headers, tablefmt="grid"))
    else:
        print(Fore.YELLOW + "\nNo cookies detected for analysis." + Style.RESET_ALL)

    # === 5. Return issue summary for main program ===
    cookie_findings: List[Dict[str, Any]] = []
    for c in issues:
        mf = c.get("MissingFlags", "")
        if "Secure" in mf and "HttpOnly" in mf:
            sev = "High"
        elif "Secure" in mf:
            sev = "High"
        elif "HttpOnly" in mf:
            sev = "Medium"
        else:
            sev = "Low"
        cookie_findings.append({
            "Category": "Cookie",
            "Name": c.get("Name"),
            "Severity": sev,
            "Description": f"Missing flags: {mf}"
        })

    return cookie_findings
