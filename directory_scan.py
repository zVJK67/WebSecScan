"""
Directory & File Exposure Scanner (safe checks)

NOTE:
This scanner performs non-destructive HTTP HEAD/GET requests only.
No authentication bypass, brute forcing, crawling, or file downloads
are attempted. Designed strictly for academic and defensive assessment.
"""

from typing import List, Dict
from urllib.parse import urljoin, urlparse
import requests
from colorama import Fore, Style
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------
# Common paths (grouped by risk tier for clarity)
# ---------------------------------------------------------
COMMON_PATHS = [
    # High risk
    "/.env", "/.git/", "/.git/config", "/.htpasswd",
    "/config.php", "/wp-config.php",
    "/backup.zip", "/backup.tar.gz", "/config.php.bak",

    # Medium risk
    "/admin/", "/admin/index.php", "/phpinfo.php",
    "/logs/", "/error_log",

    # Low / informational
    "/robots.txt", "/sitemap.xml",
    "/.gitignore", "/.DS_Store",
    "/readme.txt", "/readme.html",
    "/.well-known/security.txt",
]

INTERESTING_STATUS = {200, 401, 403, 500}

_SEV_ORDER = {"High": 3, "Medium": 2, "Low": 1}

RISK_EXPLANATIONS = {
    ".env": "Environment variables and secrets exposed",
    ".git": "Git repository metadata exposes source code",
    "config": "Configuration files may reveal sensitive settings",
    "backup": "Backup files may contain source code or credentials",
    "phpinfo": "PHP configuration disclosure reveals server internals",
    ".htpasswd": "Credential file exposed",
    "admin": "Administrative interface exposed",
    "logs": "Log files may contain sensitive information",
    "error_log": "Error logs may reveal internal paths",
    "robots": "Reveals sensitive or hidden application paths",
    "sitemap": "Exposes application structure for reconnaissance",
}


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def _normalize_url(base: str) -> str:
    parsed = urlparse(base)
    if not parsed.scheme:
        base = "http://" + base
    return base


def _severity_for(path: str, status: int) -> str:
    p = path.lower()

    if status == 200:
        if any(x in p for x in [".env", ".git", "config", "backup", ".htpasswd", "phpinfo"]):
            return "High"
        if "admin" in p or p.endswith("/"):
            return "Medium"
        return "Medium"

    if status == 401:
        return "Medium"  # confirms protected resource exists

    if status == 403:
        if any(x in p for x in [".git", "config", "backup"]):
            return "Medium"
        return "Low"

    if status >= 500:
        return "Low"

    return "Low"


def _get_risk_explanation(path: str) -> str:
    p = path.lower()
    for key, explanation in RISK_EXPLANATIONS.items():
        if key in p:
            return explanation
    return "Sensitive resource accessible"


def _overall_severity(findings: List[Dict]) -> str:
    highest = 0
    for f in findings:
        path = f.get("RelPath", "")
        status = f.get("Status", 0)
        sev = _severity_for(path, status)
        highest = max(highest, _SEV_ORDER.get(sev, 0))

    return {3: "High", 2: "Medium", 1: "Low"}.get(highest, "Info")


def _cvss_for(severity: str) -> str:
    return {
        "High": "8.2 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
        "Medium": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        "Low": "2.7 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)",
    }.get(severity, "0.0")


# ---------------------------------------------------------
# Scanner
# ---------------------------------------------------------
def scan_common_paths(base_url: str, timeout: int = 6, max_results: int = 50) -> List[Dict]:
    """
    Perform non-destructive scanning of common files/directories.
    """
    base = _normalize_url(base_url)

    session = requests.Session()
    session.headers.update({"User-Agent": "WebSecScan/DirScanner/1.1"})
    session.verify = False

    findings: List[Dict] = []
    scanned = 0

    for rel in COMMON_PATHS:
        if scanned >= max_results:
            break

        scanned += 1
        full = urljoin(base if base.endswith("/") else base + "/", rel.lstrip("/"))

        try:
            # HEAD first (lighter)
            resp = session.head(full, timeout=timeout, allow_redirects=True)

            if resp.status_code not in INTERESTING_STATUS:
                continue

            # Fallback to GET for confirmation
            resp = session.get(full, timeout=timeout, allow_redirects=True)
            status = resp.status_code

            # False-positive reduction for fake 200 pages
            if status == 200:
                content_len = len(resp.content or b"")
                content_type = resp.headers.get("Content-Type", "").lower()
                if content_len < 300 and "text/html" in content_type:
                    continue

            sev = _severity_for(rel, status)

            findings.append({
                "Category": "Directory Exposure",
                "Description": f"Path {rel} returned HTTP {status}.",
                "RelPath": rel,
                "URL": full,
                "Status": status,
                "Risk": _get_risk_explanation(rel),
                "_item_short": rel.strip("/").split("/")[-1],
            })

        except requests.RequestException:
            continue

    return findings


# ---------------------------------------------------------
# Output
# ---------------------------------------------------------
def print_dir_scan_results(findings: List[Dict]) -> None:
    print(Fore.CYAN + "\nSensitive File and Directory Exposure" + Style.RESET_ALL)
    print(Fore.MAGENTA + "══════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    if not findings:
        print(Fore.GREEN + "✓ No sensitive files or directories exposed" + Style.RESET_ALL)
        return

    overall = _overall_severity(findings)
    print("Risk Rating:")
    print(f"Severity: {overall}")
    print(f"CVSS: {_cvss_for(overall)}\n")

    print("Findings:")
    for idx, f in enumerate(findings, 1):
        print(f"{idx}. {f['RelPath']}")
        print(f"   URL: {f['URL']}")
        print(f"   Status: {f['Status']}")
        print(f"   Risk: {f['Risk']}\n")

    print(Fore.YELLOW + "Recommendations" + Style.RESET_ALL)
    print(" - Remove sensitive files from web root")
    print(" - Block access to dotfiles (.git, .env) at web server level")
    print(" - Disable directory listing")
    print(" - Rotate exposed credentials immediately")
    print(" - Apply least-privilege file permissions")

    print(Fore.MAGENTA + "══════════════════════════════════════════════════════════════" + Style.RESET_ALL)
