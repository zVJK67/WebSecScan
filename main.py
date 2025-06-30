import requests
from colorama import Fore
from tabulate import tabulate

url = "https://owasp.org/www-project-juice-shop/"
response = requests.get(url)

headers = response.headers.items()

print(Fore.CYAN + "\n📋 Response Headers:\n")
print(tabulate(headers, headers=["Header", "Value"], tablefmt="fancy_grid"))
