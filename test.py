# main.py
from banner import print_banner
from get_header import get_request, parse_headers, print_headers, print_options_response, get_allowed_methods
from http_header import analyze_security_headers, print_findings
from http_method import analyze_http_methods, print_http_method_findings
from cookie_checker import analyze_cookies
from test2 import analyze_cors
from ssl_tls import run_ssl_check, check_ssl_tls
from server_info import get_server_info, print_server_info
from findings_summary import print_summary_table, print_detailed_findings, generate_summary, export_summary_csv, normalize_findings
from path_traversal import test_path_traversal
from directory_scan import scan_common_paths, print_dir_scan_results
from export_findings import generate_interactive_html_report, export_to_json

from colorama import Fore, Style, init
import urllib.parse
import sys
import time
import webbrowser
import os
from datetime import datetime
import signal


# initialize colorama
init(autoreset=True)

def handle_interrupt(sig, frame):
    print("\n\n" + Fore.RED + "⚠️ Scan interrupted by user (Ctrl + C). Exiting safely..." + Style.RESET_ALL)
    sys.exit(0)
# Capture Ctrl+C and exit gracefully
signal.signal(signal.SIGINT, handle_interrupt)


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

    # === Step 3: Server Info Check (ENHANCED) ===
    print(Fore.CYAN + "\n[3/8] Checking server information & exposures..." + Style.RESET_ALL)
    print(Fore.YELLOW + "   → Analyzing headers, error pages, and fingerprinting patterns..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        info, server_findings = get_server_info(url, timeout=10)
        print_server_info(info, server_findings)
        
        # Optional: Show additional technical details in verbose mode
        if verbose:
            show_details = input(Fore.YELLOW + "\nShow detailed server fingerprinting analysis? (y/n): " + Style.RESET_ALL).strip().lower()
            if show_details == 'y':
                # Display header order analysis
                header_order = info.get("header_order_analysis", {})
                if header_order.get("potential_matches"):
                    print(Fore.CYAN + "\n📊 Server Fingerprint Matches:" + Style.RESET_ALL)
                    for server_type, match_info in header_order["potential_matches"].items():
                        print(f"  • {server_type}: {match_info['confidence']:.0%} confidence")
                        print(f"    Matching headers: {', '.join(match_info['matching_headers'])}")
                
                # Display error response details
                error_responses = info.get("error_responses", [])
                if error_responses:
                    print(Fore.CYAN + f"\n🔍 Error Page Analysis ({len(error_responses)} tests):" + Style.RESET_ALL)
                    for err in error_responses:
                        print(f"\n  Test: {err['test']}")
                        print(f"  Status: {err['status_code']}")
                        if err.get('server_header'):
                            print(f"  Server Header: {err['server_header']}")
                        if err.get('mentions_in_body'):
                            print(f"  Body Mentions: {', '.join(err['mentions_in_body'])}")
                
                # Display status line info
                status_line = info.get("status_line", {})
                if status_line:
                    print(Fore.CYAN + "\n📋 HTTP Status Line Details:" + Style.RESET_ALL)
                    print(f"  HTTP Version: {status_line.get('http_version')}")
                    print(f"  Status Code: {status_line.get('status_code')}")
                    print(f"  Reason Phrase: {status_line.get('reason_phrase')}")
    except Exception as e:
        print(Fore.RED + f"[ERROR] Server info check failed: {e}" + Style.RESET_ALL)
        import traceback
        if verbose:
            print(Fore.RED + traceback.format_exc() + Style.RESET_ALL)
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

    # === Step 5: CORS Security Analysis (IMPROVED) ===
    print(Fore.CYAN + "\n[5/8] Checking Cross-Origin Resource Sharing (CORS) configuration..." + Style.RESET_ALL)
    print(Fore.YELLOW + "   → Testing origin reflection, credentials handling, and preflight responses..." + Style.RESET_ALL)
    t0 = time.time()
    try:
        # Option to customize test origin in verbose mode
        if verbose:
            custom_origin = input(Fore.YELLOW + "\nUse custom test origin? (press Enter for default 'https://evil-attacker.com'): " + Style.RESET_ALL).strip()
            test_origin = custom_origin if custom_origin else "https://evil-attacker.com"
        else:
            test_origin = "https://evil-attacker.com"
        
        cors_findings = analyze_cors(url, fake_origin=test_origin)
        
        # The improved cors_checker.py already prints detailed output
        # No need for additional printing here
        
    except Exception as e:
        print(Fore.RED + f"[ERROR] CORS check failed: {e}" + Style.RESET_ALL)
        import traceback
        if verbose:
            print(Fore.RED + traceback.format_exc() + Style.RESET_ALL)
        cors_findings = []
    
    print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # CORS findings already have Category set by the improved analyzer
    # But let's ensure consistency
    cors_findings = _tag_findings_with_category(cors_findings, "CORS Security")

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
    dir_findings = _tag_findings_with_category(dir_findings, "Directory Exposure")

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

    # Tag SSL findings
    ssl_findings = _tag_findings_with_category(ssl_findings, "SSL/TLS")

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

        # === NEW: Ask if user wants to generate interactive HTML report ===
        print(Fore.CYAN + "\n" + "=" * 80 + Style.RESET_ALL)
        generate_report = input(Fore.YELLOW + "\n📊 Generate interactive HTML report? (y/n): " + Style.RESET_ALL).strip().lower()
        
        if generate_report == 'y':
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            html_filename = f"security_scan_report_{timestamp}.html"
            
            print(Fore.CYAN + f"\n🔨 Generating interactive report..." + Style.RESET_ALL)
            
            success = generate_interactive_html_report(
                findings=all_findings,
                summary=summary,
                filename=html_filename,
                target_url=url
            )
            
            if success:
                print(Fore.GREEN + f"\n✅ Report generated successfully!" + Style.RESET_ALL)
                print(Fore.CYAN + f"   📁 File: {os.path.abspath(html_filename)}" + Style.RESET_ALL)
                print(Fore.CYAN + f"   🌐 Opening in browser..." + Style.RESET_ALL)
                
                # Automatically open in browser
                try:
                    webbrowser.open('file://' + os.path.abspath(html_filename))
                    print(Fore.GREEN + "   ✓ Opened in default browser" + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"   ✗ Could not open browser: {e}" + Style.RESET_ALL)
                    print(Fore.YELLOW + f"   Please open manually: {os.path.abspath(html_filename)}" + Style.RESET_ALL)
            else:
                print(Fore.RED + "\n✗ Failed to generate report" + Style.RESET_ALL)
        
        # === LEGACY: Option for direct CSV/JSON export (without interactive HTML) ===
        else:
            export_legacy = input(Fore.YELLOW + "\nExport to CSV or JSON directly? (y/n): " + Style.RESET_ALL).strip().lower()
            
            if export_legacy == 'y':
                print(Fore.CYAN + "\nAvailable export formats:" + Style.RESET_ALL)
                print("  1. JSON  – Structured data (for analysis or integration)")
                print("  2. CSV   – Table summary (for spreadsheets)")
                print("  3. Both  – Export both formats")
                
                fmt_choice = input(Fore.YELLOW + "\nEnter your choice: " + Style.RESET_ALL).strip().lower()
                
                export_json_flag = fmt_choice in ['1', '3', 'json', 'both']
                export_csv_flag = fmt_choice in ['2', '3', 'csv', 'both']
                
                # --- JSON Export ---
                if export_json_flag:
                    json_fname = input("Enter JSON filename (default: security_scan_report.json): ").strip()
                    if not json_fname:
                        json_fname = "security_scan_report.json"
                    elif not json_fname.lower().endswith('.json'):
                        json_fname += '.json'
                    try:
                        export_to_json(all_findings, summary, filename=json_fname, target_url=url)
                    except Exception as e:
                        print(Fore.RED + f"[ERROR] export_to_json failed: {e}" + Style.RESET_ALL)
                
                # --- CSV Export ---
                if export_csv_flag:
                    csv_fname = input("Enter CSV filename (default: security_findings_summary.csv): ").strip()
                    if not csv_fname:
                        csv_fname = "security_findings_summary.csv"
                    elif not csv_fname.lower().endswith('.csv'):
                        csv_fname += '.csv'
                    try:
                        export_summary_csv(summary, csv_fname)
                    except Exception as e:
                        print(Fore.RED + f"[ERROR] export_summary_csv failed: {e}" + Style.RESET_ALL)

    else:
        print(Fore.GREEN + "\n✅ No security findings detected across all categories!" + Style.RESET_ALL)

    print(Fore.CYAN + "\n" + "=" * 80 + Style.RESET_ALL)
    print(Fore.GREEN + "Security scan complete. Thank you for using WebSecScan!" + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 80 + "\n" + Style.RESET_ALL)


if __name__ == "__main__":
    main()