"""
Directory & File Exposure Scanner (safe checks)

Usage:
    from directory_scan import scan_common_paths, print_dir_scan_results
    findings = scan_common_paths("https://example.com")
    print_dir_scan_results(findings)
"""

from typing import List, Dict
from urllib.parse import urljoin, urlparse
import requests
from colorama import Fore, Style
import urllib3

# Suppress urllib3 InsecureRequestWarning (we intentionally skip cert verification for HTTP-level tests)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common paths to probe (safe, read-only)
COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.git/", "/.env", "/.htaccess",
    "/config.php", "/config.php.bak", "/config.bak", "/backup.zip",
    "/wp-config.php", "/admin/", "/admin/index.php", "/phpinfo.php",
    "/server-status", "/.well-known/security.txt", "/.well-known/change-password",
    "/.git/config", "/.DS_Store", "/.gitignore", "/logs/", "/error_log",
    "/.htpasswd", "/README", "/readme.html", "/readme.txt", "/backup.tar.gz"
]

# "Interesting" responses to surface (presence, forbidden, auth required, server error)
INTERESTING_STATUS = {200, 401, 403, 500}

_SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2}

# Risk explanations for different file types
RISK_EXPLANATIONS = {
    ".env": "Environment variables and secrets exposed",
    "config": "Configuration files may reveal sensitive settings",
    "backup": "Backup files may contain sensitive data or source code",
    ".git": "Git repository data exposes source code and history",
    "phpinfo": "PHP configuration disclosure reveals server details",
    ".htaccess": "Apache configuration may reveal security rules",
    ".htpasswd": "Password file may expose authentication credentials",
    "admin": "Administrative interface accessible to potential attackers",
    ".DS_Store": "macOS metadata may reveal directory structure",
    "logs": "Log files may contain sensitive information",
    "error_log": "Error logs may reveal system paths and vulnerabilities",
    "readme": "Documentation may reveal version information",
    "sitemap": "Site structure disclosure aids reconnaissance",
    "robots.txt": "Reveals paths that should be hidden from crawlers",
}


def _normalize_url(base: str) -> str:
    parsed = urlparse(base)
    if not parsed.scheme:
        base = "http://" + base
    return base


def _severity_for(path: str, status: int) -> str:
    """
    Simple heuristic. Publicly reachable sensitive files => High,
    admin or directory hits => Medium, other interesting codes => Low/Medium.
    """
    p = path.lower()
    if status == 200:
        if any(x in p for x in [".env", "config", "backup", "phpinfo", ".git", ".htpasswd", "key", "passwd"]):
            return "High"
        if p.endswith("/") or "admin" in p:
            return "Medium"
        return "Medium"
    if status == 401:
        return "Medium"   # auth gate exists (interesting)
    if status == 403:
        return "Low"      # blocked (good), but still noteworthy
    if status >= 500:
        return "Low"      # server error while probing
    return "Low"


def _get_risk_explanation(path: str) -> str:
    """Get risk explanation based on file/path type"""
    p = path.lower()
    
    # Check for specific matches
    for key, explanation in RISK_EXPLANATIONS.items():
        if key in p:
            return explanation
    
    # Default explanation
    return "Sensitive file or directory accessible to unauthorized users"


def scan_common_paths(base_url: str, timeout: int = 6, max_results: int = 50) -> List[Dict]:
    """
    Scan a list of common files/directories (non-destructive).
    Returns a list of findings with:
      Category, Severity, Description, RelPath, URL, Status
    """
    base = _normalize_url(base_url)
    session = requests.Session()
    session.headers.update({"User-Agent": "WebSecScan/DirScanner/1.0"})
    # IMPORTANT: scanner design — skip TLS verification for HTTP-level checks
    session.verify = False

    findings: List[Dict] = []
    scanned = 0

    for rel in COMMON_PATHS:
        if scanned >= max_results:
            break
        scanned += 1

        full = urljoin(base if base.endswith("/") else base + "/", rel.lstrip("/"))
        try:
            resp = session.get(full, timeout=timeout, allow_redirects=True, verify=False)
            status = resp.status_code if resp is not None else None

            if status in INTERESTING_STATUS:
                sev = _severity_for(rel, status)
                risk_explanation = _get_risk_explanation(rel)
                
                findings.append({
                    "Category": "Directory Exposure",
                    "Severity": sev,
                    "Description": f"Path {rel} returned HTTP {status}.",
                    "RelPath": rel,
                    "URL": full,
                    "Status": status,
                    "Risk": risk_explanation,
                    "_item_short": rel.strip("/"),
                })
        except requests.RequestException:
            # ignore transient network errors and continue scanning
            continue

    return findings


def print_dir_scan_results(findings: List[Dict], show_counts: bool = False) -> None:
    """
    Print directory scan results in the requested format with enhanced details.
    """
    
    # Filter out "/" home directory as it's not a vulnerability
    filtered_findings = [f for f in findings if f.get("RelPath") != "/"]
    
    # Print section header
    print(Fore.CYAN + "\nSensitive File and Directory Exposure" + Style.RESET_ALL)
    print(Fore.MAGENTA + "═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    
    if not filtered_findings:
        # No findings case
        print(Fore.GREEN + "✓ No sensitive files or directories exposed" + Style.RESET_ALL)
        print("=" * 64)
        return
    
    # Calculate overall risk rating (fixed values)
    print("Risk Rating:")
    print("Severity: Medium")
    print("CVSS: 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)")
    
    print("\nFindings:")
    print(Fore.CYAN + f"``````````````````````````````````````````````````````````````````````````````````" + Style.RESET_ALL)
    
    # Print findings without severity grouping
    for idx, f in enumerate(filtered_findings, 1):
        rel = f.get("RelPath") or "-"
        url = f.get("URL") or "-"
        status = f.get("Status")
        risk = f.get("Risk") or "Sensitive resource accessible"
        
        print(f"{idx}. {rel}")
        print(f"   URL: {url}")
        
        # Show status code with readable format
        if status is not None:
            status_text = {
                200: "200 OK",
                401: "401 Unauthorized",
                403: "403 Forbidden",
                500: "500 Internal Server Error"
            }.get(status, f"{status}")
            print(f"   Status: {status_text}")
        
        print(f"   Risk: {risk}")
        print()
    
    # Recommendations section
    print(f"{Fore.YELLOW}Recommendations{Style.RESET_ALL}")
    Fore.YELLOW + "**********************************************************" + Style.RESET_ALL
    
    # Check what types of findings exist to provide targeted recommendations
    has_git = any(".git" in f.get("RelPath", "").lower() for f in filtered_findings)
    has_env = any(".env" in f.get("RelPath", "").lower() for f in filtered_findings)
    has_backup = any("backup" in f.get("RelPath", "").lower() or ".bak" in f.get("RelPath", "").lower() for f in filtered_findings)
    has_config = any("config" in f.get("RelPath", "").lower() for f in filtered_findings)
    has_admin = any("admin" in f.get("RelPath", "").lower() for f in filtered_findings)
    
    # Build targeted recommendations list
    recommendations = []
    
    if has_env:
        recommendations.append("Remove .env files from webroot immediately and rotate all secrets")
    if has_git:
        recommendations.append("Block .git/ directory at web server level (nginx/Apache config)")
    if has_config:
        recommendations.append("Remove or restrict access to configuration files")
    if has_backup:
        recommendations.append("Delete all backup files from publicly accessible directories")
    if has_admin:
        recommendations.append("Restrict admin interfaces with authentication and IP allowlisting")
    
    # Add general recommendations
    recommendations.extend([
        "Disable directory listing in web server configuration",
        "Use .htaccess or nginx rules to deny access to dotfiles",
        "Implement strict file permissions (644 for files, 755 for dirs)",
        "Remove sensitive files and folders from the webroot",
        "Review for exposed secrets and rotate if necessary"
    ])
    
    for rec in recommendations:
        print(f"   - {rec}")
    
    print(Fore.MAGENTA + "\n═══════════════════════════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
