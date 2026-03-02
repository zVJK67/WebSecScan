# cors_checker.py
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style, init
import urllib3

init(autoreset=True)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _normalize_url(url: str) -> str:
    """Ensure URL has a scheme (http/https)"""
    parsed = urlparse(url)
    if not parsed.scheme:
        return "http://" + url
    return url

def _get_session(retries: int = 2, backoff: float = 0.2) -> requests.Session:
    """Create a session with retry logic and custom headers"""
    s = requests.Session()
    retry = Retry(
        total=retries, 
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"])
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "WebSecScan/1.0"})
    # scanner design: skip TLS verification for HTTP-level checks
    s.verify = False
    return s

def _hdr(resp: Optional[requests.Response], name: str) -> Optional[str]:
    """Safely extract header from response"""
    if resp is None:
        return None
    try:
        return resp.headers.get(name)
    except Exception:
        return None

def _print_section_header(text: str) -> None:
    """Print a section header"""
    print(f"\n{Fore.WHITE}{'─' * 60}")
    print(f"{text}")
    print(f"{'─' * 60}{Style.RESET_ALL}")

# --- Main function ---
def analyze_cors(
    url: str, 
    fake_origin: str = "https://evil-attacker.com", 
    timeout: int = 10,
    verbose: bool = False
) -> List[Dict[str, Any]]:

    target = _normalize_url(url)
    session = _get_session()
    findings: List[Dict[str, Any]] = []

    # Use the fake_origin argument 
    if verbose:
        print("\nPerforming CORS test with Target URL and a Test Origin...")
        print(Fore.YELLOW + "**********************************************************" + Style.RESET_ALL)
        print("Target URL: " + target)
        print(f"Test Origin: {fake_origin}\n")
        print(Fore.YELLOW + f"Response status:" + Style.RESET_ALL)

    # Original requests (no Origin) 
    orig_get = None
    orig_options = None
    probe_get = None
    probe_options = None

    try:
        orig_get = session.get(target, timeout=timeout)
        if verbose:
            print(f"{Fore.GREEN}Original GET: {getattr(orig_get, 'status_code', 'N/A')}{Style.RESET_ALL}")
    except requests.RequestException as e:
        if verbose:
            print(f"{Fore.RED}Original GET failed: {e}{Style.RESET_ALL}")
        orig_get = None

    try:
        orig_options = session.options(target, timeout=timeout)
        if verbose:
            print(f"{Fore.GREEN}Original OPTIONS: {getattr(orig_options, 'status_code', 'N/A')}{Style.RESET_ALL}")
    except requests.RequestException as e:
        if verbose:
            print(f"{Fore.YELLOW}Original OPTIONS failed: {e}{Style.RESET_ALL}")
        orig_options = None

    # Probe with fake origin 
    probe_headers = {"Origin": fake_origin}
    try:
        probe_get = session.get(target, headers=probe_headers, timeout=timeout)
        if verbose:
            print(f"{Fore.GREEN}Probe GET (Origin): {getattr(probe_get, 'status_code', 'N/A')}{Style.RESET_ALL}")
    except requests.RequestException as e:
        if verbose:
            print(f"{Fore.YELLOW}Probe GET failed: {e}{Style.RESET_ALL}")
        probe_get = None

    preflight_headers = {
        "Origin": fake_origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "X-Test-Header"
    }
    try:
        probe_options = session.options(target, headers=preflight_headers, timeout=timeout)
        if verbose:
            print(f"{Fore.GREEN}Probe OPTIONS (Preflight): {getattr(probe_options, 'status_code', 'N/A')}{Style.RESET_ALL}")
    except requests.RequestException as e:
        if verbose:
            print(f"{Fore.YELLOW}Probe OPTIONS failed: {e}{Style.RESET_ALL}")
        probe_options = None

    # --- Extract CORS headers ---
    def cors_subset(resp: Optional[requests.Response]) -> Dict[str, Optional[str]]:
        """Extract relevant CORS headers from response"""
        return {
            "Access-Control-Allow-Origin": _hdr(resp, "Access-Control-Allow-Origin"),
            "Access-Control-Allow-Credentials": _hdr(resp, "Access-Control-Allow-Credentials"),
            "Access-Control-Allow-Methods": _hdr(resp, "Access-Control-Allow-Methods"),
            "Access-Control-Allow-Headers": _hdr(resp, "Access-Control-Allow-Headers"),
            "Access-Control-Max-Age": _hdr(resp, "Access-Control-Max-Age"),
            "Vary": _hdr(resp, "Vary"),
        }

    orig_get_h = cors_subset(orig_get)
    orig_options_h = cors_subset(orig_options)
    probe_get_h = cors_subset(probe_get)
    probe_options_h = cors_subset(probe_options)

    if verbose:
        print(Fore.YELLOW + "**********************************************************" + Style.RESET_ALL)
        print("\nTesting Result")

        def _print_headers_table(title: str, headers: Dict[str, Optional[str]]) -> None:
            """Print headers in a clean table format"""
            _print_section_header(title)
            for k, v in headers.items():
                value_color = Fore.GREEN if v else Fore.RED
                display_value = v if v else "Not Present"
                print(f"  {Fore.WHITE}{k:<40} {value_color}{display_value}{Style.RESET_ALL}")

        _print_headers_table("Original GET (no Origin)", orig_get_h)
        _print_headers_table("Original OPTIONS (no Origin)", orig_options_h)
        _print_headers_table(f"Probe GET (Origin: {fake_origin})", probe_get_h)
        _print_headers_table(f"Probe OPTIONS Preflight (Origin: {fake_origin})", probe_options_h)
        print(f"{Fore.WHITE}{'─' * 60}{Style.RESET_ALL}")

    # --- Security Analysis ---
    # Collect values from all responses (probe responses preferred)
    allow_origin = (
        probe_options_h.get("Access-Control-Allow-Origin") or 
        probe_get_h.get("Access-Control-Allow-Origin") or
        orig_options_h.get("Access-Control-Allow-Origin") or 
        orig_get_h.get("Access-Control-Allow-Origin")
    )

    allow_credentials = (
        probe_options_h.get("Access-Control-Allow-Credentials") or 
        probe_get_h.get("Access-Control-Allow-Credentials") or
        orig_options_h.get("Access-Control-Allow-Credentials") or 
        orig_get_h.get("Access-Control-Allow-Credentials")
    )

    allow_methods = (
        probe_options_h.get("Access-Control-Allow-Methods") or 
        orig_options_h.get("Access-Control-Allow-Methods")
    )

    allow_headers = (
        probe_options_h.get("Access-Control-Allow-Headers") or
        orig_options_h.get("Access-Control-Allow-Headers")
    )

    max_age = (
        probe_options_h.get("Access-Control-Max-Age") or
        orig_options_h.get("Access-Control-Max-Age")
    )

    vary_val = (
        probe_options_h.get("Vary") or 
        probe_get_h.get("Vary") or 
        orig_options_h.get("Vary") or 
        orig_get_h.get("Vary")
    )

    allow_credentials_bool = bool(
        allow_credentials and 
        str(allow_credentials).strip().lower() == "true"
    )

    wildcard_seen = allow_origin == "*"

    # --- Build findings list  ---

    # Finding type 1: Wildcard Origin (*) Allowed
    if wildcard_seen:
        findings.append({
            "Category": "CORS Security",
            "Type": "Wildcard Origin (*) Allowed",
            "Header": "Wildcard Origin (*) Allowed",  
            "_item_short": "Wildcard Origin Allowed",
            "CurrentValue": f"Access-Control-Allow-Origin: {allow_origin}",
            "Recommendation": "Specify only trusted, legitimate domains instead of using a wildcard *."
        })

    # Finding type 2: Credentials Allowed for All Origins (wildcard + credentials)
    if wildcard_seen and allow_credentials_bool:
        findings.append({
            "Category": "CORS Security",
            "Type": "Credentials Allowed for All Origins",
            "Header": "Credentials Allowed for All Origins",  
            "_item_short": "Credentials Allowed for All Origins",
            "CurrentValue": f"Access-Control-Allow-Credentials: true + Access-Control-Allow-Origin: *",
            "Recommendation": "Only enable credentials for specific trusted domains. Ensure Allow-Credentials: true is never used with Allow-Origin: *."
        })

    # Finding type 3: Unsafe Origin Reflection
    if allow_origin and allow_origin != "*":
        allowed = str(allow_origin).strip()
        if fake_origin.lower().rstrip('/') in allowed.lower():
            findings.append({
                "Category": "CORS Security",
                "Type": "Unsafe Origin Reflection",
                "Header": "Unsafe Origin Reflection", 
                "_item_short": "Unsafe Origin Reflection",
                "CurrentValue": f"Access-Control-Allow-Origin: {allowed}",      
                "Detail": "The server reflects whatever Origin the request sends, meaning it trusts unknown domains.",
                "Recommendation": "Replace dynamic origin reflection with a fixed whitelist of allowed origins. Reject unexpected or untrusted origins."
            })

    # Finding type 4: Excessive Allowed Methods (ONLY unsafe methods)
    if allow_methods:
        methods_list = [m.strip().upper() for m in str(allow_methods).split(",") if m.strip()]
        methods_set = set(methods_list)

        # Methods that can modify server state
        unsafe_methods = {"PUT", "DELETE", "PATCH"}

        exposed = methods_set.intersection(unsafe_methods)

        if exposed:
            findings.append({
                "Category": "CORS Security",
                "Type": "Excessive Allowed Methods",
                "Header": "Excessive Allowed Methods",
                "_item_short": "Excessive Allowed Methods",
                "CurrentValue": f"Access-Control-Allow-Methods: {allow_methods}",
                "Detail": (
                    "The server allows state-changing HTTP methods "
                    f"({', '.join(sorted(exposed))}) in cross-origin requests."),
                "Recommendation": "Restrict allowed methods to only the application requires (eg. GET, POST)."
            })

    # Finding type 5A/5B: Vary: Origin Header
    dynamic_cors = (
        wildcard_seen or
        allow_origin == fake_origin or
        allow_credentials_bool
    )

    if allow_origin and dynamic_cors:
        if not vary_val or "origin" not in vary_val.lower():
            findings.append({
                "Category": "CORS Security",
                "Type": "Missing 'Vary: Origin' Header",
                "Header": "Missing 'Vary: Origin' Header",
                "_item_short": "Missing Vary Origin Header",
                "Detail": (
                    "The server returns dynamic CORS responses but does not "
                    "include the Vary: Origin header, which can cause unsafe "
                    "responses to be cached and reused."
                ),
                "Recommendation": (
                    "Add Vary: Origin when the server returns different "
                    "CORS responses based on the request Origin."
                )
            })
        elif wildcard_seen or allow_origin == fake_origin or allow_credentials_bool:
            # Unsafe policy + cacheable response
            findings.append({
                "Category": "CORS Security",
                "Type": "Unsafe 'Vary: Origin' Usage",
                "Header": "Unsafe 'Vary: Origin' Usage",
                "_item_short": "Unsafe Vary Origin Usage",
                "CurrentValue": "Vary: Origin",
                "Detail": (
                    "The Vary: Origin header is present, but the underlying "
                    "CORS policy (wildcard, reflection, or credentials) is unsafe, "
                    "causing the insecure configuration to be cached."
                ),
                "Recommendation": (
                    "Fix the CORS policy first (proper whitelist, no wildcard "
                    "with credentials). Only rely on Vary: Origin after the "
                    "policy is secure."
                )
            })

    # Finding type 8: Preflight (OPTIONS) Accepts Untrusted Origins
    if probe_options and allow_origin:
        probe_allow_origin = probe_options_h.get("Access-Control-Allow-Origin")
        if probe_allow_origin and (probe_allow_origin == "*" or probe_allow_origin == fake_origin):
            if allow_credentials_bool or (allow_methods and len(allow_methods.split(',')) > 2):
                findings.append({
                    "Category": "CORS Security",
                    "Type": "Preflight (OPTIONS) Accepts Untrusted Origins",
                    "Header": "Preflight (OPTIONS) Accepts Untrusted Origins",  # For table display
                    "_item_short": "Preflight Accepts Untrusted Origins",
                    "Detail": "When the scanner sends an OPTIONS request with an untrusted Origin, the server still responds with full permissions, including credentials and multiple allowed methods.",
                    "Recommendation": "Update the preflight validation to reject unapproved origins before responding with CORS permissions."
                })

    print(Fore.CYAN + f"\nCORS Security Analysis" + Style.RESET_ALL)
    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    if findings:
        print("Risk Rating:")
        print("Severity: High")
        print("CVSS: 8.3 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N)")
        print("\nFindings:")
        print(Fore.CYAN + f"``````````````````````````````````````````````````````````````````````````````````" + Style.RESET_ALL)
        for idx, f in enumerate(findings, 1):
            print(f"{idx}. {f['Type']}")

            if f.get("CurrentValue"):
                print(f"   Current Value: {f['CurrentValue']}")

            if f.get("Detail"):
                print(f"   Detail: {f['Detail']}")

            print(
                f"   Recommendation: "
                f"{f.get('Recommendation', '')}\n"
            )

    else:
        print("✓ No findings.")

    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    return findings
