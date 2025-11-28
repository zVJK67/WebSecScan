from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style, init

# --- Helpers ---
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
    return s

def _hdr(resp: Optional[requests.Response], name: str) -> Optional[str]:
    """Safely extract header from response"""
    if resp is None:
        return None
    return resp.headers.get(name)

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
    """
    Perform comprehensive CORS security analysis.
    
    Tests:
      1. Original GET and OPTIONS (no Origin header)
      2. Probe GET with attacker Origin
      3. Probe OPTIONS preflight with attacker Origin
    
    Returns:
        List of findings with Category, Description, and Recommendation
    """
    target = _normalize_url(url)
    session = _get_session()
    findings: List[Dict[str, Any]] = []

    # Only show detailed output in verbose mode
    if verbose:
        print(f"\n{Fore.CYAN}Use custom test origin? (press Enter for default '{fake_origin}'):{Style.RESET_ALL}")
        custom_input = input().strip()
        if custom_input:
            fake_origin = custom_input

        print("**********************************************************")
        print("Target URL: " + target)
        print(f"Test Origin: {fake_origin}")

        print(f"\n{Fore.CYAN}[1/4] Sending original GET request...{Style.RESET_ALL}")
    
    # --- Step 1: Original requests (no Origin) ---
    try:
        orig_get = session.get(target, timeout=timeout)
        if verbose:
            print(f"{Fore.GREEN}✓ Status: {orig_get.status_code}{Style.RESET_ALL}")
    except requests.RequestException as e:
        if verbose:
            print(f"{Fore.RED}✗ Failed: {e}{Style.RESET_ALL}")
        orig_get = None

    if verbose:
        print(f"\n{Fore.CYAN}[2/4] Sending original OPTIONS request...{Style.RESET_ALL}")
    try:
        orig_options = session.options(target, timeout=timeout)
        if verbose:
            print(f"{Fore.GREEN}✓ Status: {orig_options.status_code}{Style.RESET_ALL}")
    except requests.RequestException as e:
        if verbose:
            print(f"{Fore.YELLOW}✗ Failed: {e}{Style.RESET_ALL}")
        orig_options = None

    # --- Step 2: Probe with fake origin ---
    if verbose:
        print(f"\n{Fore.CYAN}[3/4] Probing GET with attacker Origin...{Style.RESET_ALL}")
    probe_headers = {"Origin": fake_origin}
    try:
        probe_get = session.get(target, headers=probe_headers, timeout=timeout)
        if verbose:
            print(f"{Fore.GREEN}✓ Status: {probe_get.status_code}{Style.RESET_ALL}")
    except requests.RequestException as e:
        if verbose:
            print(f"{Fore.YELLOW}✗ Failed: {e}{Style.RESET_ALL}")
        probe_get = None

    if verbose:
        print(f"\n{Fore.CYAN}[4/4] Sending preflight OPTIONS with attacker Origin...{Style.RESET_ALL}")
    preflight_headers = {
        "Origin": fake_origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "X-Test-Header"
    }
    try:
        probe_options = session.options(target, headers=preflight_headers, timeout=timeout)
        if verbose:
            print(f"{Fore.GREEN}✓ Status: {probe_options.status_code}{Style.RESET_ALL}")
    except requests.RequestException as e:
        if verbose:
            print(f"{Fore.YELLOW}✗ Failed: {e}{Style.RESET_ALL}")
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

    # --- Display observed headers (verbose mode only) ---
    if verbose:
        print("\n**********************************************************")
        print("CORS Headers Observed")
        
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
    print("**********************************************************")

    # Collect values from all responses
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

    # --- Build findings list (will be numbered sequentially when printed) ---
    
    # Finding type 1: Wildcard Origin (*) Allowed
    if wildcard_seen:
        findings.append({
            "Category": "CORS Security",
            "Type": "Wildcard Origin (*) Allowed",
            "Detail": f"Access-Control-Allow-Origin: {allow_origin}",
            "Recommendation": "Specify only trusted, legitimate domains instead of using a wildcard *."
        })

    # Finding type 2: Credentials Allowed for All Origins (wildcard + credentials)
    if wildcard_seen and allow_credentials_bool:
        findings.append({
            "Category": "CORS Security",
            "Type": "Credentials Allowed for All Origins",
            "Detail": f"Access-Control-Allow-Credentials: true + Access-Control-Allow-Origin: *",
            "Recommendation": "Only enable credentials for specific trusted domains. Ensure Allow-Credentials: true is never used with Allow-Origin: *."
        })

    # Finding type 3: Unsafe Origin Reflection
    if allow_origin and allow_origin != "*":
        allowed = str(allow_origin).strip()
        if allowed == fake_origin:
            findings.append({
                "Category": "CORS Security",
                "Type": "Unsafe Origin Reflection",
                "Detail": f"Access-Control-Allow-Origin: {allowed}\n          -The server reflects whatever Origin the request sends, meaning it trusts unknown domains.",
                "Recommendation": "Replace dynamic origin reflection with a fixed whitelist of allowed origins. Reject unexpected or untrusted origins."
            })

    # Finding type 4: Excessive Allowed Methods
    if allow_methods:
        methods_list = [m.strip().upper() for m in str(allow_methods).split(",") if m.strip()]
        methods_set = set(methods_list)
        unsafe_methods = {"PUT", "DELETE", "PATCH"}
        exposed = methods_set.intersection(unsafe_methods)
        
        if exposed or len(methods_list) > 3:
            findings.append({
                "Category": "CORS Security",
                "Type": "Excessive Allowed Methods",
                "Detail": f"Access-Control-Allow-Methods: {allow_methods}\n          -The server allows more HTTP methods than necessary, increasing exposure.",
                "Recommendation": "Restrict allowed methods to only the application requires (eg. GET, POST)."
            })

    # Finding type 5A/5B: Vary: Origin Header
    if allow_origin and allow_origin not in ("*", "null"):
        if not vary_val or "origin" not in vary_val.lower():
            findings.append({
                "Category": "CORS Security",
                "Type": "Missing 'Vary: Origin' Header",
                "Detail": "The server does not include the Vary: Origin header.",
                "Recommendation": "Add Vary: Origin when the server returns different CORS responses depending on the request's Origin."
            })
        else:
            # Check if CORS policy is unsafe despite having Vary: Origin
            if wildcard_seen or (allow_origin == fake_origin) or allow_credentials_bool:
                findings.append({
                    "Category": "CORS Security",
                    "Type": "Unsafe 'Vary: Origin' Usage",
                    "Detail": f"Vary: Origin\n          -The header is present, but the overall CORS policy (allowed origins, credentials, reflection) is unsafe, causing the unsafe configuration to be cached.",
                    "Recommendation": "Fix the CORS policy first (proper whitelist, no wildcard with credentials). Only rely on Vary: Origin after the policy is secure."
                })

    # Finding type 6A/6B: Access-Control-Max-Age
    if not max_age:
        findings.append({
            "Category": "CORS Security",
            "Type": "Missing Access-Control-Max-Age Header",
            "Detail": "The server does not include the Access-Control-Max-Age header.",
            "Recommendation": "Set a reasonable Access-Control-Max-Age (eg. 300–600 seconds) to help browsers reuse valid preflight results without adding performance overhead."
        })
    else:
        try:
            max_age_val = int(max_age)
            if max_age_val > 86400:  # More than 24 hours
                findings.append({
                    "Category": "CORS Security",
                    "Type": "Unsafe or Excessively Long Access-Control-Max-Age",
                    "Detail": f"Access-Control-Max-Age: {max_age}\n          -The server caches CORS permissions for too long, causing outdated or incorrect policies to persist.",
                    "Recommendation": "Avoid extremely long caching durations, use moderate values (eg. 300–600 seconds)."
                })
        except ValueError:
            pass

    # Finding type 7: CORS Enabled on Endpoints That Don't Need It
    if allow_origin and not url.endswith(('/api', '/api/', '/graphql', '/v1', '/v2')):
        # Only flag if it's not obviously an API endpoint
        parsed = urlparse(url)
        if parsed.path in ('/', '', '/index.html', '/home'):
            findings.append({
                "Category": "CORS Security",
                "Type": "CORS Enabled on Endpoints That Don't Need It",
                "Detail": "The server appears to return CORS headers even for endpoints that do not require cross-origin access.",
                "Recommendation": "Only enable CORS for specific API endpoints that truly require cross-origin requests. Disable it for login pages or sensitive routes."
            })

    # Finding type 8: Preflight (OPTIONS) Accepts Untrusted Origins
    if probe_options and allow_origin:
        probe_allow_origin = probe_options_h.get("Access-Control-Allow-Origin")
        if probe_allow_origin and (probe_allow_origin == "*" or probe_allow_origin == fake_origin):
            if allow_credentials_bool or (allow_methods and len(allow_methods.split(',')) > 2):
                findings.append({
                    "Category": "CORS Security",
                    "Type": "Preflight (OPTIONS) Accepts Untrusted Origins",
                    "Detail": "When the scanner sends an OPTIONS request with an untrusted Origin, the server still responds with full permissions, including credentials and multiple allowed methods.",
                    "Recommendation": "Update the preflight validation to reject unapproved origins before responding with CORS permissions."
                })

    # --- Print findings in the desired format ---
    print("\nCORS Security Analysis")
    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    
    if findings:
        print("Risk Rating:")
        print("Severity: High")
        print("CVSS: 8.3 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N)")
        print("\nFindings:")
        print("`" * 60)
        for idx, f in enumerate(findings, 1):
            print(f"\n{idx}. {f['Type']}")
            print(f"   Detail: {f['Detail']}")
            print(f"   Recommendation: {f['Recommendation']}")
    else:
        print("✓ No findings.")
    
    print(Fore.MAGENTA + "\n═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    return findings