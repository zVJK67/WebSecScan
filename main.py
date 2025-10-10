from get_header import get_request, parse_headers, print_headers, print_options_response, get_allowed_methods
from analyze_header import analyze_security_headers, print_findings, analyze_http_methods, print_http_method_findings, print_summary
from colorama import Fore

url = input("Enter an URL to test your header: ").strip()

# Send GET request
response = get_request(url)

# Parse headers
headers = parse_headers(response)
if not headers:
    print(Fore.RED + "\n[!] Failed to retrieve headers or empty response.\n")
else:
    # Analyze security headers
    findings = analyze_security_headers(headers)
    print_findings(findings)

# Check allowed methods
methods = get_allowed_methods(url)

# Analyze unsafe HTTP methods
method_findings = analyze_http_methods(methods)

# Print all under one clear section
print_http_method_findings(method_findings, methods)

# print summary table (add after both findings have been printed)
print_summary(findings, method_findings)

# Ask if user wants to see raw headers 
raw_header = input("\nSee raw GET headers? (y/n): ").strip().lower()
if raw_header == 'y':
    print_headers(headers)

options_header = input("\nSee OPTIONS raw response? (y/n): ").strip().lower()
if options_header == 'y':
    print_options_response(url)