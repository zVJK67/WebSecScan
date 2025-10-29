import ssl
import socket
import datetime
import urllib.parse
from colorama import Fore, Style

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
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer.get("organizationName", "Unknown")

                # Expiry date
                not_after = cert.get("notAfter")
                if not_after:
                    expiry_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    result["certificate_expiry"] = expiry_date.strftime("%Y-%m-%d")

                    # Days until expiry
                    days_left = (expiry_date - datetime.datetime.utcnow()).days
                    result["days_until_expiry"] = days_left

                    # Check if certificate still valid
                    result["certificate_valid"] = days_left > 0

    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {e}"
    except socket.timeout:
        result["error"] = "Connection timed out."
    except ConnectionRefusedError:
        result["error"] = "Connection refused — likely not supporting HTTPS on port 443."
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"

    return result


def print_ssl_result(data):
    print(Fore.CYAN + "\n🔒 SSL/TLS Security Analysis" + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)

    if data["error"]:
        print(Fore.RED + f"[ERROR] {data['error']}" + Style.RESET_ALL)
        print(Fore.YELLOW + "Recommendation: Ensure the site supports HTTPS and uses a valid TLS certificate." + Style.RESET_ALL)
        print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)
        return

    print(Fore.WHITE + f"Target Host: {data['host']}")
    print(Fore.WHITE + f"HTTPS Supported: {'✅ Yes' if data['https_supported'] else '❌ No'}")
    print(Fore.WHITE + f"TLS Version: {data['tls_version'] or 'N/A'}")
    print(Fore.WHITE + f"Issuer: {data['issuer']}")
    print(Fore.WHITE + f"Certificate Valid: {'✅ Yes' if data['certificate_valid'] else '❌ No'}")
    print(Fore.WHITE + f"Expiry Date: {data['certificate_expiry'] or 'Unknown'}")

    if data["days_until_expiry"] is not None:
        print(Fore.WHITE + f"Days Until Expiry: {data['days_until_expiry']} days")
        if data["days_until_expiry"] < 30:
            print(Fore.YELLOW + "⚠️  Warning: Certificate will expire soon!" + Style.RESET_ALL)

    if not data["certificate_valid"]:
        print(Fore.RED + "❌ Invalid or expired SSL certificate detected!" + Style.RESET_ALL)
        print(Fore.YELLOW + "Recommendation: Renew or replace the SSL certificate immediately." + Style.RESET_ALL)

    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)


def run_ssl_check(target_url):
    """
    Checks whether the given URL uses HTTPS, and if so, analyzes TLS details.
    """
    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname

    if not hostname:
        print(Fore.RED + "[ERROR] Invalid URL format." + Style.RESET_ALL)
        return

    # Check if user provided HTTP URL
    if parsed.scheme and parsed.scheme.lower() == "http":
        print(Fore.YELLOW + f"\n⚠️  The URL '{target_url}' uses HTTP instead of HTTPS." + Style.RESET_ALL)
        print(Fore.YELLOW + "Recommendation: Always use HTTPS to protect data in transit." + Style.RESET_ALL)
        return

    print(Fore.WHITE + f"\nAnalyzing HTTPS configuration for {hostname}..." + Style.RESET_ALL)
    ssl_data = check_ssl_tls(hostname)
    print_ssl_result(ssl_data)
