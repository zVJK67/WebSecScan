import requests
from http.cookies import SimpleCookie
from colorama import Fore, Style
from tabulate import tabulate
import json
from datetime import datetime

# Optional: Selenium imports (only needed if user chooses to scan JS cookies)
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def analyze_cookies(url, include_js_cookies=False):
    """
    Analyze cookies set by the server and optionally capture JS-created cookies using Selenium.
    Generates a table report and saves results to a JSON file.
    """
    print(Fore.CYAN + "\n🍪 Cookie Security Analysis")
    print("=" * 36)

    all_cookies = []

    # === 1. Fetch cookies from HTTP response ===
    try:
        response = requests.get(url, timeout=10)
        set_cookie_header = response.headers.get("Set-Cookie", "")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] Failed to fetch cookies: {e}" + Style.RESET_ALL)
        return

    # Parse cookies safely using SimpleCookie
    if set_cookie_header:
        cookie_parser = SimpleCookie()
        cookie_parser.load(set_cookie_header)

        print(Fore.GREEN + "\n[+] Server-side cookies detected:")
        for name, morsel in cookie_parser.items():
            cookie_data = {
                "Name": name,
                "Value": morsel.value,
                "Domain": morsel["domain"] or "N/A",
                "Path": morsel["path"] or "N/A",
                "Secure": "Secure" in morsel.output(),
                "HttpOnly": "HttpOnly" in morsel.output(),
                "SameSite": morsel["samesite"] or "N/A"
            }
            all_cookies.append(cookie_data)

    else:
        print(Fore.YELLOW + "\n[!] No cookies found in server response." + Style.RESET_ALL)

    # === 2. Optionally fetch client-side JS cookies using Selenium ===
    if include_js_cookies:
        print(Fore.CYAN + "\n🌐 Capturing client-side (JavaScript) cookies via Selenium...")
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        js_cookies = driver.get_cookies()
        driver.quit()

        for c in js_cookies:
            cookie_data = {
                "Name": c.get("name"),
                "Value": c.get("value"),
                "Domain": c.get("domain"),
                "Path": c.get("path"),
                "Secure": c.get("secure"),
                "HttpOnly": c.get("httpOnly"),
                "SameSite": c.get("sameSite") or "N/A"
            }
            all_cookies.append(cookie_data)

        print(Fore.GREEN + f"[+] {len(js_cookies)} JavaScript cookies captured." + Style.RESET_ALL)

    # === 3. Analyze cookie flags ===
    issues = []
    for cookie in all_cookies:
        missing = []
        if not cookie["Secure"]:
            missing.append("Secure")
        if not cookie["HttpOnly"]:
            missing.append("HttpOnly")
        if cookie["SameSite"] == "N/A":
            missing.append("SameSite")

        if missing:
            cookie["MissingFlags"] = ", ".join(missing)
            issues.append(cookie)
        else:
            cookie["MissingFlags"] = "None"

    # === 4. Print formatted table report ===
    if all_cookies:
        print(Fore.WHITE + "\n📋 Cookie Report:")
        headers = ["Name", "Domain", "Secure", "HttpOnly", "SameSite", "MissingFlags"]
        table = [[
            c["Name"],
            c["Domain"],
            "✅" if c["Secure"] else "❌",
            "✅" if c["HttpOnly"] else "❌",
            c["SameSite"],
            c["MissingFlags"]
        ] for c in all_cookies]
        print(tabulate(table, headers=headers, tablefmt="grid"))

    else:
        print(Fore.YELLOW + "\nNo cookies detected for analysis." + Style.RESET_ALL)

    # === 5. Save report to JSON ===
    '''
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"cookie_report_{timestamp}.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(all_cookies, f, indent=4)

    print(Fore.GREEN + f"\n✅ Analysis complete. Report saved as: {report_file}" + Style.RESET_ALL)
    print(Fore.WHITE + "\n(Note: JS cookie capture requires Chrome WebDriver installed.)" + Style.RESET_ALL)
    

# === Main execution ===
if __name__ == "__main__":
    test_url = input("Enter a URL to analyze cookies: ").strip()
    js_option = input("Include JS cookies with Selenium? (y/n): ").strip().lower()
    include_js = js_option == "y"
    analyze_cookies(test_url, include_js)
    '''
    # === 6. Return issue summary for main program ===
    cookie_findings = []
    for c in issues:
        sev = "High" if "Secure" in c["MissingFlags"] else ("Medium" if "HttpOnly" in c["MissingFlags"] else "Low")
        cookie_findings.append({
            "Category": "Cookie",
            "Name": c["Name"],
            "Severity": sev,
            "Description": f"Missing flags: {c['MissingFlags']}"
        })

    return cookie_findings

