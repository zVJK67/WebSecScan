from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style

# --- Helpers ---
def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        return "http://" + url
    return url

def _get_session(retries: int = 2, backoff: float = 0.2) -> requests.Session:
    s = requests.Session()
    retry = Retry(total=retries, backoff_factor=backoff,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]))
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "WebSecScan/1.0"})
    return s

def _hdr(resp: Optional[requests.Response], name: str) -> Optional[str]:
    if resp is None:
        return None
    return resp.headers.get(name)

# --- Main function ---
def analyze_cors(url: str, fake_origin: str = "https://evil-attacker.com", timeout: int = 10) -> List[Dict[str, Any]]:
    """
    Perform CORS analysis:
      - original GET and OPTIONS (no Origin)
      - probe GET and OPTIONS with a fake attacker Origin
    Returns a list of findings (each finding is a dict with keys Category, Description, Severity, Recommendation, Context).
    """
    target = _normalize_url(url)
    session = _get_session()
    findings: List[Dict[str, Any]] = []

    print(Fore.CYAN + "\n🌍 CORS Security Analysis (Detailed View)" + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)

    try:
        orig_get = session.get(target, timeout=timeout)
    except requests.RequestException as e:
        print(Fore.RED + f"[ERROR] Original GET request failed: {e}" + Style.RESET_ALL)
        orig_get = None

    try:
        orig_options = session.options(target, timeout=timeout)
    except requests.RequestException:
        orig_options = None

    # Probe with fake origin
    probe_headers = {"Origin": fake_origin}
    try:
        probe_get = session.get(target, headers=probe_headers, timeout=timeout)
    except requests.RequestException:
        probe_get = None

    preflight_headers = {
        "Origin": fake_origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "X-Test-Header"
    }
    try:
        probe_options = session.options(target, headers=preflight_headers, timeout=timeout)
    except requests.RequestException:
        probe_options = None

    # Extract relevant CORS headers (use full names now)
    def cors_subset(resp: Optional[requests.Response]) -> Dict[str, Optional[str]]:
        return {
            "Access-Control-Allow-Origin": _hdr(resp, "Access-Control-Allow-Origin"),
            "Access-Control-Allow-Credentials": _hdr(resp, "Access-Control-Allow-Credentials"),
            "Access-Control-Allow-Methods": _hdr(resp, "Access-Control-Allow-Methods"),
            "Access-Control-Max-Age": _hdr(resp, "Access-Control-Max-Age"),
            "Vary": _hdr(resp, "Vary"),
        }

    orig_get_h = cors_subset(orig_get)
    orig_options_h = cors_subset(orig_options)
    probe_get_h = cors_subset(probe_get)
    probe_options_h = cors_subset(probe_options)

    # --- Print observed headers (useful for debug/report) ---
    def _print_section(title: str, headers: Dict[str, Optional[str]]) -> None:
        print(Fore.WHITE + f"\n{title}" + Style.RESET_ALL)
        print("-" * 60)
        for k, v in headers.items():
            print(f"{k}: {v or 'N/A'}")
        print("-" * 60)

    _print_section("1) Original GET response (no Origin header sent):", orig_get_h)
    _print_section("2) Original OPTIONS response (no Origin header sent):", orig_options_h)
    _print_section(f"3) Probe GET response (Origin: {fake_origin}):", probe_get_h)
    _print_section(f"4) Probe OPTIONS response (preflight, Origin: {fake_origin}):", probe_options_h)

    # --- Analysis ---
    print(Fore.WHITE + "\n🔎 Analysis (based on probe and original responses):\n" + Style.RESET_ALL)

    # pick best sources for values
    allow_origin = probe_options_h.get("Access-Control-Allow-Origin") or probe_get_h.get("Access-Control-Allow-Origin") \
                   or orig_options_h.get("Access-Control-Allow-Origin") or orig_get_h.get("Access-Control-Allow-Origin")
    allow_credentials = probe_options_h.get("Access-Control-Allow-Credentials") or probe_get_h.get("Access-Control-Allow-Credentials") \
                        or orig_options_h.get("Access-Control-Allow-Credentials") or orig_get_h.get("Access-Control-Allow-Credentials")
    allow_methods = probe_options_h.get("Access-Control-Allow-Methods") or orig_options_h.get("Access-Control-Allow-Methods")
    vary_val = probe_options_h.get("Vary") or probe_get_h.get("Vary") or orig_options_h.get("Vary") or orig_get_h.get("Vary")

    # Normalize credential header presence
    allow_credentials_bool = bool(allow_credentials and str(allow_credentials).strip().lower() == "true")

    # 1) Wildcard + credentials (critical)
    wildcard_seen = any((v == "*") for v in [
        allow_origin,
        orig_get_h.get("Access-Control-Allow-Origin"),
        orig_options_h.get("Access-Control-Allow-Origin")
    ])
    if wildcard_seen and allow_credentials_bool:
        findings.append({
            "Category": "CORS",
            "Description": "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true — invalid and critical.",
            "Severity": "High",
            "Context": "Observed in original or probe responses",
            "Recommendation": "Do not use '*' with credentials. Return explicit trusted origin(s) instead."
        })
        print(Fore.RED + "[CRITICAL] ACAO='*' with credentials=true detected.\n" + Style.RESET_ALL)

    # 2) Reflection: server echoed attacker origin back
    if allow_origin:
        allowed = str(allow_origin).strip()
        if allowed == fake_origin or fake_origin in allowed:
            findings.append({
                "Category": "CORS",
                "Description": f"Server reflected attacker Origin ({fake_origin}) in Access-Control-Allow-Origin.",
                "Severity": "High",
                "Context": "Probe response",
                "Recommendation": "Do not reflect arbitrary Origin values. Use a strict server-side whitelist."
            })
            print(Fore.RED + f"[!] Reflected attacker origin in ACAO: {allowed}" + Style.RESET_ALL)
        elif allowed == "null":
            findings.append({
                "Category": "CORS",
                "Description": "Access-Control-Allow-Origin: null returned (opaque origin).",
                "Severity": "Low",
                "Context": "Probe response",
                "Recommendation": "Check if 'null' is required; otherwise restrict CORS origins."
            })
            print(Fore.YELLOW + "[!] ACAO: null observed." + Style.RESET_ALL)
        elif allowed == "*":
            findings.append({
                "Category": "CORS",
                "Description": "Access-Control-Allow-Origin: * (wildcard) observed in response.",
                "Severity": "Medium",
                "Context": "Probe / Original responses",
                "Recommendation": "Avoid wildcard origins; use an explicit whitelist."
            })
            print(Fore.YELLOW + "[!] ACAO: * observed." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "[+] No reflection or wildcard origin found." + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "[!] No ACAO header returned in probe." + Style.RESET_ALL)
        findings.append({
            "Category": "CORS",
            "Description": "No Access-Control-Allow-Origin header in probe response.",
            "Severity": "Low",
            "Context": "Probe response",
            "Recommendation": "If cross-origin access is needed, return specific allowed origins explicitly."
        })

    # 3) Vary header check
    if allow_origin and allow_origin not in ("*", "null"):
        if "origin" not in (vary_val or "").lower():
            findings.append({
                "Category": "CORS",
                "Description": "Missing 'Vary: Origin' when returning specific Access-Control-Allow-Origin values.",
                "Severity": "Medium",
                "Context": "Observed in responses (probe/original)",
                "Recommendation": "Add 'Vary: Origin' to prevent caching issues with dynamic origins."
            })
            print(Fore.YELLOW + "[!] Missing 'Vary: Origin' header." + Style.RESET_ALL)

    # 4) Methods exposure
    if allow_methods:
        methods_set = {m.strip().upper() for m in str(allow_methods).split(",") if m.strip()}
        unsafe_methods = {"PUT", "DELETE", "PATCH"}
        exposed = methods_set.intersection(unsafe_methods)
        if exposed:
            findings.append({
                "Category": "CORS",
                "Description": f"Unsafe HTTP methods exposed via CORS/preflight: {', '.join(sorted(exposed))}",
                "Severity": "Medium",
                "Context": "Probe preflight or original OPTIONS",
                "Recommendation": "Restrict unsafe HTTP methods or require authentication."
            })
            print(Fore.YELLOW + f"[!] Unsafe methods exposed: {', '.join(sorted(exposed))}" + Style.RESET_ALL)

    # 5) Credentials allowed but no explicit origin
    if allow_credentials_bool and (allow_origin is None or allow_origin in ("", "null")):
        findings.append({
            "Category": "CORS",
            "Description": "Access-Control-Allow-Credentials is true but no explicit allowed origin returned.",
            "Severity": "Medium",
            "Context": "Probe/original responses",
            "Recommendation": "Return explicit trusted origin when credentials are allowed."
        })

    # Summary
    total = len(findings)
    print(Fore.WHITE + f"\nSummary: {total} CORS findings detected." + Style.RESET_ALL)
    if total:
        for i, f in enumerate(findings, 1):
            sev_color = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.GREEN}.get(f["Severity"], Fore.WHITE)
            print(f"\n{i}. {f['Category']} — {f['Description']}")
            print(f"   Severity: {sev_color}{f['Severity']}{Style.RESET_ALL}")
            if "Context" in f:
                print(f"   Context: {f['Context']}")
            print(f"   Recommendation: {f['Recommendation']}")
    else:
        print(Fore.GREEN + "✅ No CORS issues detected.\n" + Style.RESET_ALL)

    print(Fore.CYAN + "\nCORS analysis completed.\n" + Style.RESET_ALL)
    return findings
