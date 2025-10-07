from get_header import get_request, parse_headers, print_headers, get_allowed_methods
from analyze_header import analyze_security_headers, print_findings
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

    # Ask if user wants to see raw headers
    raw_header = input("\nSee raw headers? (y/n): ").strip().lower()
    if raw_header == 'y':
        print_headers(headers)

# Check allowed methods
methods = get_allowed_methods(url)
print(Fore.YELLOW + f"\n🔎 Allowed Methods: {methods}\n")
