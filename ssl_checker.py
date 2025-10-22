import ssl
import socket
import datetime

def check_ssl_tls(hostname):
    result = {
        "host": hostname,
        "https_supported": False,
        "tls_version": None,
        "certificate_valid": False,
        "certificate_expiry": None,
        "days_until_expiry": None,
        "issuer": None,
        "error": None
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["https_supported"] = True
                result["tls_version"] = ssock.version()

                # Extract issuer info
                issuer = dict(x[0] for x in cert["issuer"])
                result["issuer"] = issuer.get("organizationName", "Unknown")

                # Expiry date
                not_after = cert["notAfter"]
                expiry_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                result["certificate_expiry"] = expiry_date.strftime("%Y-%m-%d")

                # Days until expiry
                days_left = (expiry_date - datetime.datetime.utcnow()).days
                result["days_until_expiry"] = days_left

                # Check if certificate still valid
                if days_left > 0:
                    result["certificate_valid"] = True

    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {e}"
    except socket.timeout:
        result["error"] = "Connection timed out."
    except Exception as e:
        result["error"] = str(e)

    return result


def print_ssl_report(data):
    print("\n🔒 SSL/TLS Security Analysis")
    print("=" * 60)
    if data["error"]:
        print(f"[ERROR] {data['error']}")
        return

    print(f"Target Host: {data['host']}")
    print(f"HTTPS Supported: {'✅ Yes' if data['https_supported'] else '❌ No'}")
    print(f"TLS Version: {data['tls_version']}")
    print(f"Issuer: {data['issuer']}")
    print(f"Certificate Valid: {'✅ Yes' if data['certificate_valid'] else '❌ No'}")
    print(f"Expiry Date: {data['certificate_expiry']}  (in {data['days_until_expiry']} days)")

    if data["days_until_expiry"] and data["days_until_expiry"] < 30:
        print("⚠️  Warning: Certificate will expire soon!")

    print("=" * 60)

import urllib.parse

def run_ssl_check(target_url):
    hostname = urllib.parse.urlparse(target_url).hostname
    if not hostname:
        print("[ERROR] Invalid URL format.")
        return
    ssl_data = check_ssl_tls(hostname)
    print_ssl_report(ssl_data)


from colorama import Fore, Style
# === Step 0: Ask for URL ===
target_url = input(Fore.WHITE + "\nEnter an URL to test your header: " + Style.RESET_ALL).strip()

run_ssl_check(target_url)