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

def _print_banner(text: str, char: str = "=") -> None:
    """Print a formatted banner"""
    print(f"\n{Fore.CYAN}{text}")
    print(f"{char * 70}{Style.RESET_ALL}")

def _print_section_header(text: str) -> None:
    """Print a section header"""
    print(f"\n{Fore.WHITE}{'─' * 70}")
    print(f"{text}")
    print(f"{'─' * 70}{Style.RESET_ALL}")

# --- Main function ---
def analyze_cors(
    url: str, 
    fake_origin: str = "https://evil-attacker.com", 
    timeout: int = 10
) -> List[Dict[str, Any]]:
    """
    Perform comprehensive CORS security analysis.
    
    Tests:
      1. Original GET and OPTIONS (no Origin header)
      2. Probe GET with attacker Origin
      3. Probe OPTIONS preflight with attacker Origin
    
    Returns:
        List of findings with Category, Description, Severity, Context, and Recommendation
    """
    target = _normalize_url(url)
    session = _get_session()
    findings: List[Dict[str, Any]] = []

    _print_banner("🔒 CORS Security Analysis", "=")
    print(f"{Fore.WHITE}Target: {Fore.CYAN}{target}")
    print(f"{Fore.WHITE}Test Origin: {Fore.YELLOW}{fake_origin}{Style.RESET_ALL}\n")

    # --- Step 1: Original requests (no Origin) ---
    print(f"{Fore.CYAN}[1/4] Sending original GET request...{Style.RESET_ALL}")
    try:
        orig_get = session.get(target, timeout=timeout)
        print(f"{Fore.GREEN}✓ Status: {orig_get.status_code}{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.RED}✗ Failed: {e}{Style.RESET_ALL}")
        orig_get = None

    print(f"\n{Fore.CYAN}[2/4] Sending original OPTIONS request...{Style.RESET_ALL}")
    try:
        orig_options = session.options(target, timeout=timeout)
        print(f"{Fore.GREEN}✓ Status: {orig_options.status_code}{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.YELLOW}✗ Failed: {e}{Style.RESET_ALL}")
        orig_options = None

    # --- Step 2: Probe with fake origin ---
    print(f"\n{Fore.CYAN}[3/4] Probing GET with attacker Origin...{Style.RESET_ALL}")
    probe_headers = {"Origin": fake_origin}
    try:
        probe_get = session.get(target, headers=probe_headers, timeout=timeout)
        print(f"{Fore.GREEN}✓ Status: {probe_get.status_code}{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.YELLOW}✗ Failed: {e}{Style.RESET_ALL}")
        probe_get = None

    print(f"\n{Fore.CYAN}[4/4] Sending preflight OPTIONS with attacker Origin...{Style.RESET_ALL}")
    preflight_headers = {
        "Origin": fake_origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "X-Test-Header"
    }
    try:
        probe_options = session.options(target, headers=preflight_headers, timeout=timeout)
        print(f"{Fore.GREEN}✓ Status: {probe_options.status_code}{Style.RESET_ALL}")
    except requests.RequestException as e:
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

    # --- Display observed headers ---
    _print_banner("📋 CORS Headers Observed", "=")
    
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

    # --- Security Analysis ---
    _print_banner("🔍 Security Analysis", "=")

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

    # --- Check 1: Wildcard + Credentials (CRITICAL) ---
    wildcard_seen = allow_origin == "*"
    
    if wildcard_seen and allow_credentials_bool:
        findings.append({
            "Category": "CORS Misconfiguration",
            "Description": "CRITICAL: Access-Control-Allow-Origin is '*' while credentials are enabled",
            "Severity": "Critical",
            "Context": "This is an invalid CORS configuration per spec",
            "Recommendation": "Never use wildcard with credentials. Return explicit trusted origin(s)."
        })
        print(f"{Fore.RED}✗ CRITICAL: Wildcard origin (*) with credentials enabled!{Style.RESET_ALL}")

    # --- Check 2: Origin Reflection (HIGH RISK) ---
    if allow_origin and allow_origin != "*":
        allowed = str(allow_origin).strip()
        
        if allowed == fake_origin:
            findings.append({
                "Category": "CORS Misconfiguration",
                "Description": f"Server reflects arbitrary origin - returned {fake_origin}",
                "Severity": "High",
                "Context": "Attacker origin was echoed in Access-Control-Allow-Origin",
                "Recommendation": "Implement strict origin whitelist. Never reflect user-supplied Origin."
            })
            print(f"{Fore.RED}✗ HIGH RISK: Server reflects attacker origin!{Style.RESET_ALL}")
            
        elif allowed == "null":
            findings.append({
                "Category": "CORS Configuration",
                "Description": "Origin 'null' is allowed (opaque origin)",
                "Severity": "Medium",
                "Context": "Allows requests from data URLs, sandboxed iframes, etc.",
                "Recommendation": "Avoid allowing 'null' origin unless specifically required."
            })
            print(f"{Fore.YELLOW}⚠ Warning: 'null' origin is allowed{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✓ Origin appears controlled: {allowed}{Style.RESET_ALL}")
    
    elif wildcard_seen and not allow_credentials_bool:
        findings.append({
            "Category": "CORS Configuration",
            "Description": "Wildcard origin (*) without credentials",
            "Severity": "Low",
            "Context": "Public API - allows all origins to read responses",
            "Recommendation": "Consider if this is intentional for a public API."
        })
        print(f"{Fore.YELLOW}⚠ Info: Wildcard origin without credentials (may be intentional){Style.RESET_ALL}")
    
    elif not allow_origin:
        print(f"{Fore.YELLOW}⚠ No CORS headers present{Style.RESET_ALL}")
        findings.append({
            "Category": "CORS Configuration",
            "Description": "No Access-Control-Allow-Origin header present",
            "Severity": "Info",
            "Context": "CORS is not enabled or not configured",
            "Recommendation": "If cross-origin access is needed, configure CORS properly."
        })

    # --- Check 3: Vary Header ---
    if allow_origin and allow_origin not in ("*", "null"):
        if not vary_val or "origin" not in vary_val.lower():
            findings.append({
                "Category": "CORS Configuration",
                "Description": "Missing 'Vary: Origin' header with dynamic origin",
                "Severity": "Medium",
                "Context": "Can cause caching issues with CDNs and proxies",
                "Recommendation": "Add 'Vary: Origin' to prevent cache poisoning."
            })
            print(f"{Fore.YELLOW}⚠ Missing 'Vary: Origin' header{Style.RESET_ALL}")

    # --- Check 4: Unsafe Methods Exposed ---
    if allow_methods:
        methods_list = [m.strip().upper() for m in str(allow_methods).split(",") if m.strip()]
        methods_set = set(methods_list)
        unsafe_methods = {"PUT", "DELETE", "PATCH"}
        exposed = methods_set.intersection(unsafe_methods)
        
        if exposed:
            findings.append({
                "Category": "CORS Configuration",
                "Description": f"Unsafe HTTP methods exposed: {', '.join(sorted(exposed))}",
                "Severity": "Medium",
                "Context": f"Methods allowed: {', '.join(methods_list)}",
                "Recommendation": "Restrict dangerous methods or require strong authentication."
            })
            print(f"{Fore.YELLOW}⚠ Unsafe methods exposed: {', '.join(sorted(exposed))}{Style.RESET_ALL}")

    # --- Check 5: Credentials Without Explicit Origin ---
    if allow_credentials_bool and (not allow_origin or allow_origin in ("", "null")):
        findings.append({
            "Category": "CORS Misconfiguration",
            "Description": "Credentials enabled without explicit allowed origin",
            "Severity": "Medium",
            "Context": "Access-Control-Allow-Credentials is true",
            "Recommendation": "Always specify explicit trusted origin when credentials are enabled."
        })
        print(f"{Fore.YELLOW}⚠ Credentials enabled without explicit origin{Style.RESET_ALL}")

    # --- Summary Report ---
    _print_banner("📊 Summary Report", "=")
    
    total = len(findings)
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    
    for f in findings:
        severity_counts[f["Severity"]] = severity_counts.get(f["Severity"], 0) + 1
    
    print(f"\n{Fore.WHITE}Total Findings: {Fore.CYAN}{total}{Style.RESET_ALL}")
    if severity_counts["Critical"]:
        print(f"{Fore.RED}  Critical: {severity_counts['Critical']}{Style.RESET_ALL}")
    if severity_counts["High"]:
        print(f"{Fore.RED}  High: {severity_counts['High']}{Style.RESET_ALL}")
    if severity_counts["Medium"]:
        print(f"{Fore.YELLOW}  Medium: {severity_counts['Medium']}{Style.RESET_ALL}")
    if severity_counts["Low"]:
        print(f"{Fore.GREEN}  Low: {severity_counts['Low']}{Style.RESET_ALL}")
    if severity_counts["Info"]:
        print(f"{Fore.CYAN}  Info: {severity_counts['Info']}{Style.RESET_ALL}")

    if total == 0:
        print(f"\n{Fore.GREEN}✅ No CORS security issues detected!{Style.RESET_ALL}\n")
    else:
        print(f"\n{Fore.WHITE}{'─' * 70}{Style.RESET_ALL}")
        
        for i, f in enumerate(findings, 1):
            severity_colors = {
                "Critical": Fore.RED,
                "High": Fore.RED,
                "Medium": Fore.YELLOW,
                "Low": Fore.GREEN,
                "Info": Fore.CYAN
            }
            sev_color = severity_colors.get(f["Severity"], Fore.WHITE)
            
            print(f"\n{Fore.WHITE}[{i}] {f['Category']}{Style.RESET_ALL}")
            print(f"    {Fore.WHITE}Issue: {f['Description']}{Style.RESET_ALL}")
            print(f"    {Fore.WHITE}Severity: {sev_color}{f['Severity']}{Style.RESET_ALL}")
            print(f"    {Fore.WHITE}Context: {Fore.CYAN}{f['Context']}{Style.RESET_ALL}")
            print(f"    {Fore.WHITE}Fix: {Fore.GREEN}{f['Recommendation']}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print("CORS analysis completed successfully!")
    print(f"{'=' * 70}{Style.RESET_ALL}\n")
    
    return findings