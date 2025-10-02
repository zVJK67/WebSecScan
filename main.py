from http_utils import get_request, parse_headers, print_headers, get_allowed_methods
from colorama import Fore

url = "https://owasp.org/www-project-juice-shop/"

# Send GET request
response = get_request(url)

# Parse headers
headers = parse_headers(response)

# Print headers (clean version)
print_headers(headers)

# Check allowed methods
methods = get_allowed_methods(url)
print(Fore.YELLOW + f"\n🔎 Allowed Methods: {methods}\n")
