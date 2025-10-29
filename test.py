# main.py
from banner import print_banner
from get_header import get_request, parse_headers, print_headers, print_options_response, get_allowed_methods
from http_header import analyze_security_headers, print_findings
from http_method import analyze_http_methods, print_http_method_findings
from cookie_checker import analyze_cookies
from cors_checker import analyze_cors
from ssl_tls import run_ssl_check, check_ssl_tls
from server_info import get_server_info, print_server_info
from findings_summary import print_summary
from colorama import Fore, Style, init
import urllib.parse
import sys

# initialize colorama
init(autoreset=True)

def normalize_and_validate_url(raw_url: str) -> str:
    """
    Ensure URL has a scheme. Return normalized URL or raise ValueError if invalid.
    """
    if not raw_url:
        raise ValueError("Empty URL provided.")
    parsed = urllib.parse.urlparse(raw_url)
    if not parsed.scheme:
        # assume http by default if user omitted scheme
        raw_url = "http://" + raw_url
        parsed = urllib.parse.urlparse(raw_url)
    if not parsed.hostname:
        raise ValueError("Invalid URL (no hostname found). Provide full URL like 'https://example.com' or 'example.com'.")
    return raw_url

def _ensure_field(finding: dict, key: str, default: str) -> None:
    """Helper to set default field if missing (mutates finding)."""
    if key not in finding or finding.get(key) is None:
        finding[key] = default

def _tag_findings_with_category(findings_list, category_name):
    """
    Ensure each finding dict in findings_list has a Category, Severity and Description.
    This mutates the provided list in-place.
    """
    for f in (findings_list or []):
        # Category
        if "Category" not in f or not f.get("Category"):
            f["Category"] = category_name

        # Severity fallback
        if "Severity" not in f or not f.get("Severity"):
            # try to infer from common keys, otherwise default to Low
            f["Severity"] = f.get("Severity") or "Low"

        # Description fallback
        if "Description" not in f or not f.get("Description"):
            # prefer Recommendation, Status, Header, Name
            if f.get("Recommendation"):
                f["Description"] = f.get("Recommendation")
            elif f.get("Status"):
                f["Description"] = str(f.get("Status"))
            elif f.get("Header"):
                f["Description"] = str(f.get("Header"))
            elif f.get("Name"):
                f["Description"] = str(f.get("Name"))
            else:
                f["Description"] = ""

def main():
    print_banner()

    # === Step 0: Ask for URL ===
    raw = input(Fore.WHITE + "\nEnter an URL to scan (e.g. example.com or https://example.com): " + Style.RESET_ALL).strip()
    try:
        url = normalize_and_validate_url(raw)
    except ValueError as e:
        print(Fore.RED + f"[ERROR] {e}" + Style.RESET_ALL)
        sys.exit(1)

    print(Fore.YELLOW + f"\nNormalized target URL: {url}" + Style.RESET_ALL)

    # Prepare holders for findings
    header_findings = []
    method_findings = []
    server_findings = []
    cookie_findings = []
    cors_findings = []
    ssl_findings = []

    # === Step 1: Header Check ===
    print(Fore.CYAN + "\n[1/6] Checking HTTP headers..." + Style.RESET_ALL)
    try:
        response = get_request(url)
        headers = parse_headers(response)
        if not headers:
            print(Fore.RED + "\n[!] Failed to retrieve headers or empty response.\n" + Style.RESET_ALL)
        else:
            header_findings = analyze_security_headers(headers)
            print_findings(header_findings)

            raw_header = input("\nSee raw GET headers? (y/n): ").strip().lower()
            if raw_header == 'y':
                print_headers(headers)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Header check failed: {e}" + Style.RESET_ALL)
        header_findings = []

    # === Step 2: HTTP Method Check ===
    print(Fore.CYAN + "\n[2/6] Checking HTTP methods..." + Style.RESET_ALL)
    try:
        methods = get_allowed_methods(url)
        method_findings = analyze_http_methods(methods)
        print_http_method_findings(method_findings, methods)

        options_header = input("\nSee OPTIONS raw response? (y/n): ").strip().lower()
        if options_header == 'y':
            print_options_response(url)
    except Exception as e:
        print(Fore.RED + f"[ERROR] HTTP method check failed: {e}" + Style.RESET_ALL)
        method_findings = []

    # === Step 3: Server Info Check ===
    print(Fore.CYAN + "\n[3/6] Checking server information & exposures..." + Style.RESET_ALL)
    try:
        info, server_findings = get_server_info(url)
        print_server_info(info, server_findings)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Server info check failed: {e}" + Style.RESET_ALL)
        server_findings = []

    # === Step 4: Cookie Security Analysis ===
    print(Fore.CYAN + "\n[4/6] Performing Cookie Security Analysis..." + Style.RESET_ALL)
    try:
        capture_js = input("Capture JS-created cookies via Selenium? (y/n): ").strip().lower() == "y"
        cookie_findings = analyze_cookies(url, include_js_cookies=capture_js)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Cookie check failed: {e}" + Style.RESET_ALL)
        cookie_findings = []

    # === Step 5: CORS Security Analysis ===
    print(Fore.CYAN + "\n[5/6] Checking Cross-Origin Resource Sharing (CORS) configuration..." + Style.RESET_ALL)
    try:
        cors_findings = analyze_cors(url)
    except Exception as e:
        print(Fore.RED + f"[ERROR] CORS check failed: {e}" + Style.RESET_ALL)
        cors_findings = []

    # === Step 6: SSL/TLS Check ===
    print(Fore.CYAN + "\n[6/6] Checking SSL/TLS configuration..." + Style.RESET_ALL)
    try:
        run_ssl_check(url)  # prints details to console
        # collect a concise structured finding for the summary
        try:
            ssl_data = check_ssl_tls(urllib.parse.urlparse(url).hostname)
            if ssl_data.get("error"):
                ssl_findings = [{
                    "Category": "SSL/TLS",
                    "Severity": "High",
                    "Description": f"SSL/TLS error: {ssl_data.get('error')}"
                }]
            else:
                if not ssl_data.get("https_supported"):
                    ssl_findings = [{
                        "Category": "SSL/TLS",
                        "Severity": "High",
                        "Description": "HTTPS not supported; site is served over plain HTTP."
                    }]
                else:
                    # certificate not valid -> high; expiring soon -> medium
                    if not ssl_data.get("certificate_valid"):
                        ssl_findings = [{
                            "Category": "SSL/TLS",
                            "Severity": "High",
                            "Description": "Invalid or expired TLS certificate detected."
                        }]
                    elif ssl_data.get("days_until_expiry") is not None and ssl_data.get("days_until_expiry") < 30:
                        ssl_findings = [{
                            "Category": "SSL/TLS",
                            "Severity": "Medium",
                            "Description": f"TLS certificate will expire in {ssl_data.get('days_until_expiry')} days."
                        }]
        except Exception:
            ssl_findings = []
    except Exception as e:
        print(Fore.RED + f"[ERROR] SSL/TLS check failed: {e}" + Style.RESET_ALL)
        ssl_findings = []

    # === Final: Combined Summary ===
    print(Fore.GREEN + "\n[Summary] All checks completed. Generating findings summary..." + Style.RESET_ALL)

    # Tag findings with appropriate categories so summary shows per-category rows
    _tag_findings_with_category(header_findings, "Headers")
    _tag_findings_with_category(method_findings, "HTTP Methods")
    _tag_findings_with_category(server_findings, "Server")
    _tag_findings_with_category(cookie_findings, "Cookies")
    _tag_findings_with_category(cors_findings, "CORS")
    _tag_findings_with_category(ssl_findings, "SSL/TLS")

    # Combine "other" categories into one list (server, cookies, cors, ssl)
    other_findings = []
    other_findings.extend(server_findings or [])
    other_findings.extend(cookie_findings or [])
    other_findings.extend(cors_findings or [])
    other_findings.extend(ssl_findings or [])

    # Use the updated print_summary (returns a machine-readable summary dict)
    summary = print_summary(header_findings or [], method_findings or [], other_findings or [])

    # Show small hint that summary object was produced (you can save it later)
    print(Fore.WHITE + "\nSummary data object produced (in-memory). You can export it to JSON if needed." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
