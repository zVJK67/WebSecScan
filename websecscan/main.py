# main.py
import os
import sys
import time
import signal
import requests
import argparse
import ipaddress
import webbrowser
import urllib.parse
from datetime import datetime
from colorama import Fore, Style, init
from collections import defaultdict
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from websecscan.banner import print_banner
from websecscan.http_client import parse_headers
from websecscan.http_header import analyze_security_headers, print_findings
from websecscan.http_method import check_and_print_http_methods
from websecscan.server_info import get_server_info, print_server_info
from websecscan.cookie_checker import analyze_cookies
from websecscan.cors_checker import analyze_cors
from websecscan.directory_scan import scan_common_paths, print_dir_scan_results
from websecscan.path_traversal import test_path_traversal, print_path_traversal_results
from websecscan.ssl_tls import run_ssl_check
from websecscan.findings_summary import normalize_findings, print_summary_table, compute_cvss_overrides_from_findings, CATEGORY_CVSS_MAP, normalize_category_for_cvss
from websecscan.export_findings import generate_interactive_html_report
from websecscan.vulnerability_definitions import VULNERABILITY_DEFINITIONS
from websecscan.email_service import start_email_server

init(autoreset=True)

def handle_interrupt(sig, frame):
    print("\n\n" + Fore.RED + "⚠️ Scan interrupted by user (Ctrl + C). Exiting safely..." + Style.RESET_ALL)
    sys.exit(0)
# Capture Ctrl+C and exit 
signal.signal(signal.SIGINT, handle_interrupt)


import ipaddress

def normalize_and_validate_url(raw_url: str) -> str:
    """Normalize and validate URL format."""
    if not raw_url:
        raise ValueError("Empty URL provided.")

    parsed = urllib.parse.urlparse(raw_url)

    # Add scheme if missing
    if not parsed.scheme:
        raw_url = "http://" + raw_url
        parsed = urllib.parse.urlparse(raw_url)

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL format (no hostname found).")

    # Allow localhost explicitly
    if hostname == "localhost":
        return raw_url

    # Allow IP addresses
    try:
        ipaddress.ip_address(hostname)
        return raw_url
    except ValueError:
        pass

    # Enforce public domain format
    if "." not in hostname:
        raise ValueError("Invalid domain format (e.g. example.com).")

    return raw_url


def check_target_availability(url: str, timeout: int = 5):
    """Check if target URL is reachable."""
    try:
        response = requests.head(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False
        )

        # If HEAD not allowed, fallback to GET
        if response.status_code in (405, 501):
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=False
            )

        return response.status_code

    except requests.exceptions.RequestException:
        return None



def _tag_findings_with_category(findings_list, category_name):
    """
    Normalize findings with the proper category name.
    Returns a new list (doesn't mutate the original).
    """
    return normalize_findings(findings_list, force_category=category_name)


AVAILABLE_MODULES = {
    "headers",
    "methods",
    "server",
    "cookies",
    "cors",
    "dir",
    "path",
    "ssl",
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog="websecscan",
        description="WebSecScan - Web Security Misconfiguration Scanner"
    )

    parser.add_argument(
        "-u", "--url",
        help="Target URL (e.g. https://example.com)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output to inspect raw responses and other technical details"
    )

    parser.add_argument(
        "--path-tests",
        type=int,
        default=None,
        help="Number of path traversal test cases (default: prompt / 300)"
    )

    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Do not generate HTML report"
    )

    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open HTML report in browser"
    )

    parser.add_argument(
        "--skip",
        help="Comma-separated modules to skip (headers,methods,server,cookies,cors,dir,path,ssl)"
    )

    parser.add_argument(
        "--only",
        help="Comma-separated modules to run only (headers,methods,server,cookies,cors,dir,path,ssl)"
    )

    return parser.parse_args()


def resolve_enabled_modules(args):
    enabled = set(AVAILABLE_MODULES)

    if args.only:
        selected = {m.strip().lower() for m in args.only.split(",")}
        invalid = selected - AVAILABLE_MODULES
        if invalid:
            print(Fore.RED + f"[ERROR] Invalid module(s): {', '.join(invalid)}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"Valid modules: {', '.join(sorted(AVAILABLE_MODULES))}" + Style.RESET_ALL)
            sys.exit(1)
        return selected

    if args.skip:
        skipped = {m.strip().lower() for m in args.skip.split(",")}
        invalid = skipped - AVAILABLE_MODULES
        if invalid:
            print(Fore.RED + f"[ERROR] Invalid module(s): {', '.join(invalid)}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"Valid modules: {', '.join(sorted(AVAILABLE_MODULES))}" + Style.RESET_ALL)
            sys.exit(1)
        return enabled - skipped

    return enabled


def main():

    print_banner()

    start_email_server()

    args = parse_args()
    enabled_modules = resolve_enabled_modules(args)

    # === Step 0: Get and normalize URL (CLI or interactive) ===
    if args.url:
        raw = args.url.strip()
    else:
        raw = input(
            Fore.WHITE +
            "\nEnter an URL to scan (e.g. example.com or https://example.com): "
            + Style.RESET_ALL
        ).strip()

    try:
        url = normalize_and_validate_url(raw)
    except ValueError as e:
        print(Fore.RED + f"[ERROR] {e}" + Style.RESET_ALL)
        sys.exit(1)

    print(Fore.YELLOW + f"\nNormalized target URL: {url}" + Style.RESET_ALL)

    # === Availability Check ===
    status = check_target_availability(url)

    if status is None:
        print(Fore.RED + "[ERROR] Target is unreachable or does not exist." + Style.RESET_ALL)
        sys.exit(1)

    print(Fore.GREEN + f"[OK] Target reachable (HTTP {status})" + Style.RESET_ALL)


    if args.url:
        verbose = args.verbose
    else:
        verbose = input("\n[?] Enable verbose output? (y/n): ").strip().lower() == 'y'

    # Use raw requests for initial probes (verify disabled so expired/untrusted certs don't block scan)
    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
    except Exception:
        response = None

    try:
        head_resp = requests.head(url, timeout=10, allow_redirects=True, verify=False)
    except Exception:
        head_resp = None

    # Show initial status early to explain behavior on non-200 pages (e.g., 404 paths)
    try:
        head_resp = requests.head(url, timeout=6, allow_redirects=True, verify=False)
        if head_resp is None or getattr(head_resp, "status_code", 0) in (405, 501):
            head_resp = requests.get(url, timeout=6, allow_redirects=True, verify=False)
        if head_resp is not None:
            print(Fore.WHITE + f"Initial HTTP Status: {head_resp.status_code} {getattr(head_resp, 'reason', '')}" + Style.RESET_ALL)
    except Exception:
        pass

    # Prepare holders for findings
    header_findings = []
    method_findings = []
    server_findings = []
    cookie_findings = []
    cors_findings = []
    dir_findings = []      
    pt_findings = []
    ssl_findings = []
       

    # === Step 1: Header Check ===
    if "headers" in enabled_modules:
        print(Fore.CYAN + "\n[1/8] Checking HTTP headers..." + Style.RESET_ALL)
        t0 = time.time()
        try:
            try:
                response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            except Exception:
                response = None

            headers = parse_headers(response)
            if not headers:
                print(Fore.RED + "\n[!] Failed to retrieve headers or empty response.\n" + Style.RESET_ALL)
            else:
                header_findings = analyze_security_headers(headers)
                print_findings(header_findings, headers, verbose=verbose)
        except Exception as e:
            print(Fore.RED + f"[ERROR] Header check failed: {e}" + Style.RESET_ALL)
        print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

        header_findings = _tag_findings_with_category(header_findings, "HTTP Security Headers")

    # === Step 2: HTTP Method Check ===
    if "methods" in enabled_modules:
        print(Fore.CYAN + "\n[2/8] Checking HTTP methods..." + Style.RESET_ALL)
        t0 = time.time()
        try:
            method_findings = check_and_print_http_methods(url, verbose=verbose, timeout=6)
        except Exception as e:
            print(Fore.RED + f"[ERROR] HTTP method check failed: {e}" + Style.RESET_ALL)
            method_findings = []
        print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

        method_findings = _tag_findings_with_category(method_findings, "HTTP Methods")

    # === Step 3: Server Info Check ===
    if "server" in enabled_modules:
        print(Fore.CYAN + "\n[3/8] Checking for exposed server details..." + Style.RESET_ALL)

        t0 = time.time()
        try:
            info, server_findings = get_server_info(url, timeout=10)
            print_server_info(info, server_findings, verbose=verbose)

        except Exception as e:
            print(Fore.RED + f"[ERROR] Server info check failed: {e}" + Style.RESET_ALL)
            import traceback
            if verbose:
                print(Fore.RED + traceback.format_exc() + Style.RESET_ALL)
        print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

        server_findings = _tag_findings_with_category(server_findings, "Server Info")

    # === Step 4: Cookie Security Analysis ===
    if "cookies" in enabled_modules:
        print(Fore.CYAN + "\n[4/8] Checking cookie security..." + Style.RESET_ALL)
        t0 = time.time()
        try:
            capture_js = True
            cookie_findings = analyze_cookies(url, verbose=verbose, include_js_cookies=capture_js)

            server_side_cookies = []
            client_side_cookies = []
            
            for finding in cookie_findings:
                scope = finding.get("Scope", "")
                if "Server-Side" in scope:
                    server_side_cookies.append(finding)
                elif "Client-Side" in scope:
                    client_side_cookies.append(finding)
                else:
                    server_side_cookies.append(finding)
            
            server_side_cookies = _tag_findings_with_category(server_side_cookies, "Cookie Security (Server-Side)")
            client_side_cookies = _tag_findings_with_category(client_side_cookies, "Cookie Security (Client-Side)")
            
            # Merge back together
            cookie_findings = server_side_cookies + client_side_cookies

        except Exception as e:
            print(Fore.RED + f"[ERROR] Cookie check failed: {e}" + Style.RESET_ALL)
            cookie_findings = []

        print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

    # === Step 5: CORS Security Analysis ===
    if "cors" in enabled_modules:
        print(Fore.CYAN + "\n[5/8] Checking Cross-Origin Resource Sharing (CORS) configuration..." + Style.RESET_ALL)
        t0 = time.time()
        try:
            cors_findings = analyze_cors(url, fake_origin="https://evil-attacker.com", verbose=verbose)
            
        except Exception as e:
            print(Fore.RED + f"[ERROR] CORS check failed: {e}" + Style.RESET_ALL)
            import traceback
            if verbose:
                print(Fore.RED + traceback.format_exc() + Style.RESET_ALL)
            cors_findings = []
        
        print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

        cors_findings = _tag_findings_with_category(cors_findings, "CORS Security")

    # === Step 6: Directory & File Exposure  ===
    if "dir" in enabled_modules:
        print(Fore.CYAN + "\n[6/8] Scanning for common directory & file exposures..." + Style.RESET_ALL)
        t0 = time.time()
        try:
            dir_findings = scan_common_paths(url, timeout=6, max_results=50)
            print_dir_scan_results(dir_findings)
        except Exception as e:
            print(Fore.RED + f"[ERROR] Directory scan failed: {e}" + Style.RESET_ALL)
            dir_findings = []
        print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

        dir_findings = _tag_findings_with_category(dir_findings, "Directory Exposure")

    # === Step 7: Path Traversal ===
    if "path" in enabled_modules:
        print(Fore.CYAN + "\n[7/8] Checking for basic Path Traversal patterns..." + Style.RESET_ALL)
        
        if args.path_tests is not None:
            max_tests = args.path_tests
        else:
            test_count_input = input(
                "\nHow many test run? (press Enter for default run 300): "
            ).strip()
            if test_count_input:
                try:
                    max_tests = int(test_count_input)
                except ValueError:
                    print(Fore.YELLOW + "Invalid input, using default (300)" + Style.RESET_ALL)
                    max_tests = 300
            else:
                max_tests = 300
        
        t0 = time.time()
        try:
            
            pt_findings = test_path_traversal(
                base_url=url,
                timeout=10,
                max_tests=max_tests,
                verbose=verbose
            )
            pt_findings = _tag_findings_with_category(pt_findings, "Path Traversal")
            print_path_traversal_results(pt_findings)
        except Exception as e:
            print(Fore.RED + f"[ERROR] Path Traversal check failed: {e}" + Style.RESET_ALL)
            pt_findings = []
        print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

     # === Step 8: SSL/TLS Check ===
    if "ssl" in enabled_modules:
        print(Fore.CYAN + "\n[8/8] Checking SSL/TLS configuration..." + Style.RESET_ALL)
        t0 = time.time()
        try:
            ssl_findings = run_ssl_check(url, verbose=verbose)
        except Exception as e:
            print(Fore.RED + f"[ERROR] SSL/TLS check failed: {e}" + Style.RESET_ALL)
            import traceback
            if verbose:
                traceback.print_exc()
            ssl_findings = []
        print(Fore.WHITE + f"(completed in {time.time() - t0:.2f}s)" + Style.RESET_ALL)

        ssl_findings = _tag_findings_with_category(ssl_findings, "SSL/TLS")

    # Aggregate all findings and display summary table
    print(Fore.BLUE + "\nGenerating Summary..." + Style.RESET_ALL)

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

    # Normalize findings (ensures Category/Severity/Description present and removes clear "safe" items)
    normalized = normalize_findings(all_findings, exclude_safe=True)

    # Helper functions for CVSS/Severity extraction
    def _numeric_cvss(cvss):
        try:
            return float(str(cvss).split()[0])
        except Exception:
            return 0.0

    def _severity_from_cvss(score: float) -> str:
        if score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        return "Low"

    # Group findings by category
    grouped = defaultdict(list)
    for f in normalized:
        grouped[f["Category"]].append(f)

    # STEP 1: Compute dynamic CVSS overrides (for special rules)
    cvss_overrides = compute_cvss_overrides_from_findings(normalized)

    # STEP 2: Build summary with proper fallback hierarchy
    summary = {}

    for category, flist in grouped.items():
        cvss_vector = ""  
        
        # Priority 1: Check for dynamic override
        if category in cvss_overrides:
            override = cvss_overrides[category]
            severity = override["severity"]
            cvss_score = override["cvss"]
            cvss_vector = override.get("cvss_vector", "")
            cvss_display = str(cvss_score)
        else:
            # Priority 2: Use category-level defaults from CATEGORY_CVSS_MAP
            normalized_cat = normalize_category_for_cvss(category)
            cat_defaults = CATEGORY_CVSS_MAP.get(normalized_cat, {})
            
            if cat_defaults:
                severity = cat_defaults.get("severity", "Low")
                cvss_score = cat_defaults.get("cvss", "N/A")
                cvss_vector = cat_defaults.get("cvss_vector", "")
                cvss_display = str(cvss_score)
            else:
                # Priority 3: Last resort - extract max from per-finding CVSS
                scores = [
                    _numeric_cvss(f.get("CVSS"))
                    for f in flist
                    if f.get("CVSS") is not None
                ]
                
                max_score = max(scores) if scores else 0.0
                severity = _severity_from_cvss(max_score) if max_score > 0 else "Low"
                cvss_display = f"{max_score:.1f}" if max_score > 0 else "—"
                cvss_vector = ""  
        
        summary[category] = {
            "severity": severity,
            "cvss": cvss_display,
            "cvss_vector": cvss_vector,  
            "count": len(flist)
        }
        
    # STEP 3: Print the summary table
    for category in summary.keys():
        vuln_def = VULNERABILITY_DEFINITIONS.get(category, {})
        display_name = vuln_def.get("DisplayName")
        
        # Fallback to manual mapping if not in definitions
        if not display_name:
            display_name_map = {
                "HTTP Security Headers": "Misconfigured HTTP Security Header",
                "Server Info": "Server Information Disclosure",
                "Cookie Security (Server-Side)": "Improper Cookie and Session Security Configuration",
                "Cookie Security (Client-Side)": "Improper Cookie and Session Security Configuration",
                "CORS Security": "Cross-Origin Resource Sharing (CORS) Misconfiguration",
                "Directory Exposure": "Sensitive Directory and File Exposure",
                "Path Traversal": "Path Traversal Vulnerability",
                "SSL/TLS": "Weak or Misconfigured SSL/TLS",
                "HTTP Methods": "HTTP Methods"
            }
            display_name = display_name_map.get(category, category)
        
        summary[category]["display_name"] = display_name

    print_summary_table(summary, title="Security Findings Summary")

    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_filename = f"security_scan_report_{timestamp}.html"

    success = True

    if not args.no_html:

        generate_interactive_html_report(
            findings=all_findings,   
            summary=summary,
            filename=html_filename,
            target_url=url
        )

    if success:
        print(Fore.GREEN + f"\n✅ Scan completed successfully!" + Style.RESET_ALL)
        if not args.no_html:
            print(Fore.CYAN + f"   📁 HTML Report: {os.path.abspath(html_filename)}" + Style.RESET_ALL)

    else:
        print(Fore.RED + "\n✗ Failed to generate report" + Style.RESET_ALL)

    print(Fore.BLUE + "\n========================================================================================================================" + Style.RESET_ALL)
    print(Fore.BLUE + "                                Thank you for using WebSecScan" + Style.RESET_ALL)
    print(Fore.BLUE + "========================================================================================================================" + Style.RESET_ALL)

    if success and not args.no_open and not args.no_html:

        if args.url:
            # CLI mode → auto open
            webbrowser.open('file://' + os.path.abspath(html_filename))
        else:
            # Interactive → wait for user
            input(Fore.MAGENTA + "\nPress Enter to view the interactive HTML report..." + Style.RESET_ALL)
            webbrowser.open('file://' + os.path.abspath(html_filename))

if __name__ == "__main__":
    main()
