# main.py
'''
from banner import print_banner
from get_header import get_request, parse_headers, print_headers, print_options_response, get_allowed_methods
from http_header import analyze_security_headers, print_findings
from http_method import analyze_http_methods, print_http_method_findings
from cookie_checker import analyze_cookies
from cors_checker import analyze_cors
from ssl_tls import run_ssl_check, check_ssl_tls
from server_info import get_server_info, print_server_info
from findings_summary import print_summary_table, print_detailed_findings, generate_summary
from path_traversal import test_path_traversal  # Path Traversal module
from directory_scan import scan_common_paths, print_dir_scan_results  # <-- NEW: Directory scan

from colorama import Fore, Style, init
import urllib.parse
import sys
import time


# initialize colorama
init(autoreset=True)


def normalize_and_validate_url(raw_url: str) -> str:
    """Ensure URL has a scheme. Return normalized URL or raise ValueError if invalid."""
    if not raw_url:
        raise ValueError("Empty URL provided.")
    parsed = urllib.parse.urlparse(raw_url)
    if not parsed.scheme:
        raw_url = "http://" + raw_url
        parsed = urllib.parse.urlparse(raw_url)
    if not parsed.hostname:
        raise ValueError("Invalid URL (no hostname found). Provide full URL like 'https://example.com' or 'example.com'.")
    return raw_url


def _tag_findings_with_category(findings_list, category_name):
    """
    Ensure each finding dict in findings_list has a Category, Severity and Description.
    This mutates the provided list in-place.
    """
    for f in (findings_list or []):
        if not f.get("Category"):
            f["Category"] = category_name
        if not f.get("Severity"):
            f["Severity"] = "Low"
        if not f.get("Description"):
            f["Description"] = (
                f.get("Recommendation")
                or f.get("Status")
                or f.get("Header")
                or f.get("Name")
                or ""
            )


def _print_path_traversal_findings(pt_findings):
    """Pretty, grouped output for path traversal results."""
    if not pt_findings:
        return

    for f in pt_findings:
        print()
        print(Fore.WHITE + "Path Traversal" + Style.RESET_ALL)
        print(Fore.WHITE + "---------------------------------------" + Style.RESET_ALL)
        sev_color = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.GREEN}.get(f.get("Severity", "Low"), Fore.WHITE)
        print(f"Severity: {sev_color}{f.get('Severity', 'Low')}{Style.RESET_ALL}")

        endpoint = f.get("Endpoint") or f.get("Path") or "/"
        print(f"Endpoint: {endpoint}")

        payloads = f.get("Payloads") or []
        if payloads:
            print("\nPayloads triggering:")
            for p in payloads:
                print(f"  {p}")

        if f.get("Behavior"):
            print(f"\nBehavior: {f['Behavior']}")

        interp = f.get("Interpretation")
        if interp:
            print(f"\nPossible interpretation: {interp}")

        if f.get("Recommendation"):
            print("\nRecommendation:")
            for line in f["Recommendation"].split("\n"):
                print(line)

        if f.get("Details"):
            print(f"\nDetails: {f['Details']}")

        if f.get("Status") is not None:
            print(f"HTTP Status (example): {f['Status']}")


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

    # Verbosity toggle (controls noisy prints like raw header/OPTIONS dumps)
    verbose = input("Verbose output (raw headers / OPTIONS details)? (y/n): ").strip().lower() == 'y'

    # Show initial status early to explain behavior on non-200 pages (e.g., 404 paths)
    try:
        head_resp = get_request(url, method="HEAD")
        if head_resp is None or getattr(head_resp, "status_code", 0) in (405, 501):
            head_resp = get_request(url, method="GET")
        if head_resp is not None:
            print(Fore.WHITE + f"Initial HTTP Status: {head_resp.status_code} {head_resp.reason}" + Style.RESET_ALL)
    except Exception:
        pass

    # Prepare holders for findings
    header_findings = []
    method_findings = []
    server_findings = []
    dir_findings = []      # NEW: Directory scan findings
    cookie_findings = []
    cors_findings = []
    ssl_findings = []
    pt_findings = []       # Path Traversal

    # === Step 1: Header Check ===
    print(Fore.CYAN + "\n[1/8] Checking HTTP headers..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        response = get_request(url)
        headers = parse_headers(response)
        if not headers:
            print(Fore.RED + "\n[!] Failed to retrieve headers or empty response.\n" + Style.RESET_ALL)
        else:
            header_findings = analyze_security_headers(headers)
            print_findings(header_findings)
            if verbose:
                if input("\nSee raw GET headers? (y/n): ").strip().lower() == 'y':
                    print_headers(headers)
            print(Fore.WHITE + "Note: Headers shown are from the scanned path; CDNs/proxies may alter them." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Header check failed: {e}" + Style.RESET_ALL)
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # === Step 2: HTTP Method Check ===
    print(Fore.CYAN + "\n[2/8] Checking HTTP methods..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        methods = get_allowed_methods(url)
        method_findings = analyze_http_methods(methods)
        print_http_method_findings(method_findings, methods)
        if verbose:
            if input("\nSee OPTIONS raw response? (y/n): ").strip().lower() == 'y':
                print_options_response(url)
    except Exception as e:
        print(Fore.RED + f"[ERROR] HTTP method check failed: {e}" + Style.RESET_ALL)
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # === Step 3: Server Info Check ===
    print(Fore.CYAN + "\n[3/8] Checking server information & exposures..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        info, server_findings = get_server_info(url)
        print_server_info(info, server_findings)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Server info check failed: {e}" + Style.RESET_ALL)
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # === Step 4: Cookie Security Analysis ===
    print(Fore.CYAN + "\n[4/8] Performing Cookie Security Analysis..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        capture_js = input("Capture JS-created cookies via Selenium? (y/n): ").strip().lower() == "y" if verbose else False
        cookie_findings = analyze_cookies(url, include_js_cookies=capture_js)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Cookie check failed: {e}" + Style.RESET_ALL)
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # === Step 5: CORS Security Analysis ===
    print(Fore.CYAN + "\n[5/8] Checking Cross-Origin Resource Sharing (CORS) configuration..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        cors_findings = analyze_cors(url)
    except Exception as e:
        print(Fore.RED + f"[ERROR] CORS check failed: {e}" + Style.RESET_ALL)
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # === Step 6: Directory & File Exposure  ===
    print(Fore.CYAN + "\n[6/8] Scanning for common directory & file exposures..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        dir_findings = scan_common_paths(url, timeout=6, max_results=50)
        print_dir_scan_results(dir_findings)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Directory scan failed: {e}" + Style.RESET_ALL)
        dir_findings = []
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # === Step 7: Path Traversal ===
    print(Fore.CYAN + "\n[7/8] Checking for basic Path Traversal patterns..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        pt_findings = test_path_traversal(
            base_url=url,
            timeout=10,
            max_tests=300,     # adjust if needed
            verbose=verbose
        )
        _tag_findings_with_category(pt_findings, "Path Traversal")
        _print_path_traversal_findings(pt_findings)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Path Traversal check failed: {e}" + Style.RESET_ALL)
        pt_findings = []
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # === Step 8: SSL/TLS Check ===
    print(Fore.CYAN + "\n[8/8] Checking SSL/TLS configuration..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        run_ssl_check(url)  # prints details to console
        try:
            ssl_data = check_ssl_tls(urllib.parse.urlparse(url).hostname)
            if ssl_data.get("error"):
                ssl_findings = [{"Category": "SSL/TLS", "Severity": "High", "Description": f"SSL/TLS error: {ssl_data.get('error')}"}]
            elif not ssl_data.get("https_supported"):
                ssl_findings = [{"Category": "SSL/TLS", "Severity": "High", "Description": "HTTPS not supported; site is served over plain HTTP."}]
            elif not ssl_data.get("certificate_valid"):
                ssl_findings = [{"Category": "SSL/TLS", "Severity": "High", "Description": "Invalid or expired TLS certificate detected."}]
            elif ssl_data.get("days_until_expiry") is not None and ssl_data.get("days_until_expiry") < 30:
                ssl_findings = [{"Category": "SSL/TLS", "Severity": "Medium", "Description": f"TLS certificate will expire in {ssl_data.get('days_until_expiry')} days."}]
        except Exception:
            ssl_findings = []
    except Exception as e:
        print(Fore.RED + f"[ERROR] SSL/TLS check failed: {e}" + Style.RESET_ALL)
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)


     # === Final: Combined Summary ===
    print(Fore.GREEN + "\n[Summary] All checks completed. Generating findings summary..." + Style.RESET_ALL)

    # De-dupe: remove "Server" header finding from header_findings to avoid double counting with Server category
    header_findings = [
        f for f in (header_findings or [])
        if not (f.get("Header") == "Server")
    ]

    # Combine "other" categories into one list (server, cookies, cors, ssl, path traversal, dir)
    other_findings = (server_findings or []) + (cookie_findings or []) + (cors_findings or []) + (ssl_findings or []) + (pt_findings or []) + (dir_findings or [])

    # Use findings_summary.print_summary to tag, dedupe and print final table
    summary = print_summary(header_findings or [], method_findings or [], other_findings or [])

    # Short action cue
    high = summary["counts"]["High"]
    med = summary["counts"]["Medium"]
    if high > 0:
        print(Fore.RED + "Next step: Fix HIGH issues first (e.g., remove exposed secrets/backups, harden CORS, hide server versions, validate file paths)." + Style.RESET_ALL)
    elif med > 0:
        print(Fore.YELLOW + "Next step: Address MEDIUM issues next (e.g., Vary: Origin, cookie flags, traversal heuristics)." + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "Great! No High/Medium issues detected." + Style.RESET_ALL)

    print(Fore.WHITE + "\nSummary data object produced (in-memory). You can export it to JSON if needed." + Style.RESET_ALL)


if __name__ == "__main__":
    main()
'''

# main.py
from banner import print_banner
from get_header import get_request, parse_headers, print_headers, print_options_response, get_allowed_methods
from http_header import analyze_security_headers, print_findings
from http_method import analyze_http_methods, print_http_method_findings
from cookie_checker import analyze_cookies
from cors_checker import analyze_cors
from ssl_tls import run_ssl_check, check_ssl_tls
from server_info import get_server_info, print_server_info
from findings_summary import print_summary_table, print_detailed_findings, generate_summary, export_summary_csv, normalize_findings
from path_traversal import test_path_traversal  # Path Traversal module
from directory_scan import scan_common_paths, print_dir_scan_results  # Directory scan

from colorama import Fore, Style, init
import urllib.parse
import sys
import time


# initialize colorama
init(autoreset=True)


def normalize_and_validate_url(raw_url: str) -> str:
    """Ensure URL has a scheme. Return normalized URL or raise ValueError if invalid."""
    if not raw_url:
        raise ValueError("Empty URL provided.")
    parsed = urllib.parse.urlparse(raw_url)
    if not parsed.scheme:
        raw_url = "http://" + raw_url
        parsed = urllib.parse.urlparse(raw_url)
    if not parsed.hostname:
        raise ValueError("Invalid URL (no hostname found). Provide full URL like 'https://example.com' or 'example.com'.")
    return raw_url


def _tag_findings_with_category(findings_list, category_name):
    """
    Normalize findings with the proper category name.
    Returns a new list (doesn't mutate the original).
    """
    return normalize_findings(findings_list, force_category=category_name)


def _print_path_traversal_findings(pt_findings):
    """Pretty, grouped output for path traversal results."""
    if not pt_findings:
        return

    for f in pt_findings:
        print()
        print(Fore.WHITE + "Path Traversal" + Style.RESET_ALL)
        print(Fore.WHITE + "---------------------------------------" + Style.RESET_ALL)
        sev_color = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.GREEN}.get(f.get("Severity", "Low"), Fore.WHITE)
        print(f"Severity: {sev_color}{f.get('Severity', 'Low')}{Style.RESET_ALL}")

        endpoint = f.get("Endpoint") or f.get("Path") or "/"
        print(f"Endpoint: {endpoint}")

        payloads = f.get("Payloads") or []
        if payloads:
            print("\nPayloads triggering:")
            for p in payloads:
                print(f"  {p}")

        if f.get("Behavior"):
            print(f"\nBehavior: {f['Behavior']}")

        interp = f.get("Interpretation")
        if interp:
            print(f"\nPossible interpretation: {interp}")

        if f.get("Recommendation"):
            print("\nRecommendation:")
            for line in f["Recommendation"].split("\n"):
                print(line)

        if f.get("Details"):
            print(f"\nDetails: {f['Details']}")

        if f.get("Status") is not None:
            print(f"HTTP Status (example): {f['Status']}")


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

    # Verbosity toggle (controls noisy prints like raw header/OPTIONS dumps)
    verbose = input("Verbose output (raw headers / OPTIONS details)? (y/n): ").strip().lower() == 'y'

    # Show initial status early to explain behavior on non-200 pages (e.g., 404 paths)
    try:
        head_resp = get_request(url, method="HEAD")
        if head_resp is None or getattr(head_resp, "status_code", 0) in (405, 501):
            head_resp = get_request(url, method="GET")
        if head_resp is not None:
            print(Fore.WHITE + f"Initial HTTP Status: {head_resp.status_code} {head_resp.reason}" + Style.RESET_ALL)
    except Exception:
        pass

    # Prepare holders for findings
    header_findings = []
    method_findings = []
    server_findings = []
    dir_findings = []      # Directory scan findings
    cookie_findings = []
    cors_findings = []
    ssl_findings = []
    pt_findings = []       # Path Traversal

    # === Step 1: Header Check ===
    print(Fore.CYAN + "\n[1/8] Checking HTTP headers..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        response = get_request(url)
        headers = parse_headers(response)
        if not headers:
            print(Fore.RED + "\n[!] Failed to retrieve headers or empty response.\n" + Style.RESET_ALL)
        else:
            header_findings = analyze_security_headers(headers)
            print_findings(header_findings)
            if verbose:
                if input("\nSee raw GET headers? (y/n): ").strip().lower() == 'y':
                    print_headers(headers)
            print(Fore.WHITE + "Note: Headers shown are from the scanned path; CDNs/proxies may alter them." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Header check failed: {e}" + Style.RESET_ALL)
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # Tag header findings with proper category
    header_findings = _tag_findings_with_category(header_findings, "Security Headers")

    # === Step 2: HTTP Method Check ===
    print(Fore.CYAN + "\n[2/8] Checking HTTP methods..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        methods = get_allowed_methods(url)
        method_findings = analyze_http_methods(methods)
        print_http_method_findings(method_findings, methods)
        if verbose:
            if input("\nSee OPTIONS raw response? (y/n): ").strip().lower() == 'y':
                print_options_response(url)
    except Exception as e:
        print(Fore.RED + f"[ERROR] HTTP method check failed: {e}" + Style.RESET_ALL)
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # Tag method findings with proper category
    method_findings = _tag_findings_with_category(method_findings, "HTTP Methods")

    # === Step 3: Server Info Check ===
    print(Fore.CYAN + "\n[3/8] Checking server information & exposures..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        info, server_findings = get_server_info(url)
        print_server_info(info, server_findings)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Server info check failed: {e}" + Style.RESET_ALL)
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # Tag server findings with proper category
    server_findings = _tag_findings_with_category(server_findings, "Server Information")

    # === Step 4: Cookie Security Analysis ===
    print(Fore.CYAN + "\n[4/8] Performing Cookie Security Analysis..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        capture_js = input("Capture JS-created cookies via Selenium? (y/n): ").strip().lower() == "y" if verbose else False
        cookie_findings = analyze_cookies(url, include_js_cookies=capture_js)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Cookie check failed: {e}" + Style.RESET_ALL)
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # Tag cookie findings with proper category
    cookie_findings = _tag_findings_with_category(cookie_findings, "Cookie Security")

    # === Step 5: CORS Security Analysis ===
    print(Fore.CYAN + "\n[5/8] Checking Cross-Origin Resource Sharing (CORS) configuration..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        cors_findings = analyze_cors(url)
    except Exception as e:
        print(Fore.RED + f"[ERROR] CORS check failed: {e}" + Style.RESET_ALL)
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # CORS findings already have Category set

    # === Step 6: Directory & File Exposure  ===
    print(Fore.CYAN + "\n[6/8] Scanning for common directory & file exposures..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        dir_findings = scan_common_paths(url, timeout=6, max_results=50)
        print_dir_scan_results(dir_findings)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Directory scan failed: {e}" + Style.RESET_ALL)
        dir_findings = []
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # Directory findings already have Category set

    # === Step 7: Path Traversal ===
    print(Fore.CYAN + "\n[7/8] Checking for basic Path Traversal patterns..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        pt_findings = test_path_traversal(
            base_url=url,
            timeout=10,
            max_tests=300,     # adjust if needed
            verbose=verbose
        )
        pt_findings = _tag_findings_with_category(pt_findings, "Path Traversal")
        _print_path_traversal_findings(pt_findings)
    except Exception as e:
        print(Fore.RED + f"[ERROR] Path Traversal check failed: {e}" + Style.RESET_ALL)
        pt_findings = []
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # === Step 8: SSL/TLS Check ===
    print(Fore.CYAN + "\n[8/8] Checking SSL/TLS configuration..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        run_ssl_check(url)  # prints details to console
        try:
            ssl_data = check_ssl_tls(urllib.parse.urlparse(url).hostname)
            if ssl_data.get("error"):
                ssl_findings = [{"Category": "SSL/TLS", "Severity": "High", "Description": f"SSL/TLS error: {ssl_data.get('error')}"}]
            elif not ssl_data.get("https_supported"):
                ssl_findings = [{"Category": "SSL/TLS", "Severity": "High", "Description": "HTTPS not supported; site is served over plain HTTP."}]
            elif not ssl_data.get("certificate_valid"):
                ssl_findings = [{"Category": "SSL/TLS", "Severity": "High", "Description": "Invalid or expired TLS certificate detected."}]
            elif ssl_data.get("days_until_expiry") is not None and ssl_data.get("days_until_expiry") < 30:
                ssl_findings = [{"Category": "SSL/TLS", "Severity": "Medium", "Description": f"TLS certificate will expire in {ssl_data.get('days_until_expiry')} days."}]
        except Exception:
            ssl_findings = []
    except Exception as e:
        print(Fore.RED + f"[ERROR] SSL/TLS check failed: {e}" + Style.RESET_ALL)
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # ========================================================================
    # === FINDINGS SUMMARY: Aggregate all findings and display summary table
    # ========================================================================
    print(Fore.CYAN + "\n" + "=" * 80 + Style.RESET_ALL)
    print(Fore.CYAN + "SCAN COMPLETED - GENERATING SUMMARY" + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 80 + Style.RESET_ALL)

    # Combine all findings into one list
    all_findings = []
    all_findings.extend(header_findings or [])
    all_findings.extend(method_findings or [])
    all_findings.extend(server_findings or [])
    all_findings.extend(cookie_findings or [])
    all_findings.extend(cors_findings or [])
    all_findings.extend(dir_findings or [])
    all_findings.extend(pt_findings or [])
    all_findings.extend(ssl_findings or [])

    # Generate and print summary table
    if all_findings:
        summary = generate_summary(all_findings)
        print_summary_table(summary, title="🔍 Security Scan Results Summary")

        # Ask if user wants detailed findings
        if input(Fore.YELLOW + "\nView detailed findings for a specific category? (y/n): " + Style.RESET_ALL).strip().lower() == 'y':
            print("\nAvailable categories:")
            categories = sorted(set(f.get("Category", "Unknown") for f in all_findings))
            for idx, cat in enumerate(categories, 1):
                print(f"  {idx}. {cat}")
            
            try:
                choice = input(Fore.YELLOW + "\nEnter category number (or 'all' for everything): " + Style.RESET_ALL).strip()
                if choice.lower() == 'all':
                    print_detailed_findings(all_findings)
                else:
                    cat_idx = int(choice) - 1
                    if 0 <= cat_idx < len(categories):
                        print_detailed_findings(all_findings, category_filter=categories[cat_idx])
                    else:
                        print(Fore.RED + "Invalid category number." + Style.RESET_ALL)
            except (ValueError, IndexError):
                print(Fore.RED + "Invalid input." + Style.RESET_ALL)

        # Ask if user wants to export to CSV
        if input(Fore.YELLOW + "\nExport summary to CSV? (y/n): " + Style.RESET_ALL).strip().lower() == 'y':
            filename = input("Enter filename (default: security_findings_summary.csv): ").strip()
            if not filename:
                filename = "security_findings_summary.csv"
            elif not filename.endswith('.csv'):
                filename += '.csv'
            
            try:
                export_summary_csv(summary, filename)
            except Exception as e:
                print(Fore.RED + f"[ERROR] Failed to export CSV: {e}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "\n✅ No security findings detected across all categories!" + Style.RESET_ALL)

    print(Fore.CYAN + "\n" + "=" * 80 + Style.RESET_ALL)
    print(Fore.GREEN + "Security scan complete. Thank you for using WebSecScan!" + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 80 + "\n" + Style.RESET_ALL)


if __name__ == "__main__":
    main()