from banner import print_banner
from get_header import get_request, parse_headers, print_headers, print_options_response, get_allowed_methods
from http_header import analyze_security_headers, print_findings
from http_method import analyze_http_methods, print_http_method_findings
from cookie_checker import analyze_cookies
from cors_checker import analyze_cors
from ssl_checker import run_ssl_check
from server_info import get_server_info, print_server_info
from findings_summary import print_summary
from colorama import Fore, Style

print_banner()

# === Step 0: Ask for URL ===
url = input(Fore.WHITE + "\nEnter an URL to test your header: " + Style.RESET_ALL).strip()

# === Step 1: Header Check ===
print(Fore.CYAN + "\n[1/4] Checking HTTP headers..." + Style.RESET_ALL)

response = get_request(url)
headers = parse_headers(response)
if not headers:
    print(Fore.RED + "\n[!] Failed to retrieve headers or empty response.\n" + Style.RESET_ALL)
    findings = []
else:
    findings = analyze_security_headers(headers)
    print_findings(findings)

raw_header = input("\nSee raw GET headers? (y/n): ").strip().lower()
if raw_header == 'y':
    print_headers(headers)

# === Step 2: HTTP Method Check ===
print(Fore.CYAN + "\n[2/4] Checking HTTP methods..." + Style.RESET_ALL)
methods = get_allowed_methods(url)
method_findings = analyze_http_methods(methods)
print_http_method_findings(method_findings, methods)

options_header = input("\nSee OPTIONS raw response? (y/n): ").strip().lower()
if options_header == 'y':
    print_options_response(url)

# === Step 4: Server Info Check ===
info, server_findings = get_server_info(url)
print_server_info(info, server_findings)

# === Step 4: Cookie Security Analysis ===
print(Fore.CYAN + "\n[3/4] Performing Cookie Security Analysis..." + Style.RESET_ALL)
cookie_findings = analyze_cookies(url, include_js_cookies=True)

# === Step 5: CORS Security Analysis ===
print(Fore.CYAN + "\n[4/5] Checking Cross-Origin Resource Sharing (CORS) configuration..." + Style.RESET_ALL)
cors_findings = analyze_cors(url)

# === Step 6: Combined Summary ===
print(Fore.GREEN + "\n[5/5] All security misconfiguration checks completed!" + Style.RESET_ALL)
print_summary(findings, method_findings, cookie_findings + cors_findings + server_findings)
