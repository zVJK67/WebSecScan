"""
Security Findings Summary Generator

This module aggregates findings from multiple security scanners and generates
a summary table ordered by severity.

Usage:
    from findings_summary import generate_summary, print_summary_table
    
    # Collect findings from all scanners
    all_findings = []
    all_findings.extend(dir_scan_findings)
    all_findings.extend(cors_findings)
    all_findings.extend(ssl_findings)
    
    # Generate and print summary
    summary = generate_summary(all_findings)
    cvss_overrides = compute_cvss_overrides_from_findings(all_findings)
    print_summary_table(summary, cvss_overrides=cvss_overrides)
"""

from typing import List, Dict, Any
from collections import defaultdict
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


# Predefined CVSS mapping for each category
# In findings_summary.py, ensure CATEGORY_CVSS_MAP has entries for all categories
CATEGORY_CVSS_MAP = {
    "Security Headers": {
        "severity": "Low",
        "cvss": "3.1",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    },
    "HTTP Method": {
        "severity": "Medium",
        "cvss": "5.3",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "Server Information": {
        "severity": "Low",
        "cvss": "3.1",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "Cookie Security": {
        "severity": "High",
        "cvss": "7.8",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    },
    "CORS Security": {
        "severity": "High",
        "cvss": "8.3",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"
    },
    "Directory Exposure": {
        "severity": "High",   
        "cvss": "8.2",         
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    "Path Traversal": {
        "severity": "High",
        "cvss": "7.5",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    "SSL/TLS": {
        "severity": "Medium",
        "cvss": "5.3",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    }
}


def normalize_category_for_cvss(category: str) -> str:
    """
    Normalize category names to match CATEGORY_CVSS_MAP keys.
    """
    mapping = {
        "HTTP Security Headers": "Security Headers",
        "Cookie Security (Client-Side)": "Cookie Security",
        "Cookie Security (Server-Side)": "Cookie Security",
        "Server Info": "Server Information",
        "HTTP Methods": "HTTP Method"
    }
    return mapping.get(category, category)


def normalize_findings(findings: List[Dict[str, Any]], force_category: str = None, exclude_safe: bool = True) -> List[Dict[str, Any]]:
    """
    Normalize findings to ensure they all have Category, Severity, and Description.
    If force_category is provided, it will override any existing Category.
    
    Args:
        findings: List of finding dictionaries
        force_category: Optional category name to force on all findings
        exclude_safe: If True, exclude findings that are informational/non-issues only
        
    Returns:
        Normalized list of findings
    """
    normalized = []
    
    for f in (findings or []):
        # Create a copy to avoid mutating the original
        finding = f.copy()
        
        # Skip "safe" findings if exclude_safe is True
        if exclude_safe:
            status = str(finding.get("Status", "")).lower()
            
            # IMPORTANT: Only exclude if it's CLEARLY a "good" status
            # Be very specific to avoid false exclusions
            truly_safe_statuses = [
                "safe",                    # HTTP Methods: Status="Safe"
                "not exposed",            # Server Info: Status="Not exposed"
                "configured correctly",   # Headers: Status="Configured correctly"
            ]
            
            # Check if status exactly matches or is a safe variant
            is_safe = False
            for safe_status in truly_safe_statuses:
                if status == safe_status or status.startswith(safe_status):
                    is_safe = True
                    break
            
            # Additional check: if it explicitly says things are OK in the description/recommendation
            if not is_safe:
                desc = str(finding.get("Description", "")).lower()
                rec = str(finding.get("Recommendation", "")).lower()
                
                # These phrases indicate informational/good findings
                good_phrases = [
                    "no issues detected",
                    "properly configured",
                    "looks acceptable",
                    "set appropriately",
                    "no unsafe",
                    "no commonly unsafe",
                ]
                
                if any(phrase in desc or phrase in rec for phrase in good_phrases):
                    is_safe = True
            
            if is_safe:
                continue
        
        # Force category if specified (this fixes the duplication issue)
        if force_category:
            finding["Category"] = force_category
        elif not finding.get("Category"):
            # Fallback to "Unknown" if no category at all
            finding["Category"] = "Unknown"
        
        # Ensure Severity exists
        if not finding.get("Severity") and finding.get("Category") != "Directory Exposure":
            finding["Severity"] = "Low"
        
        # Ensure Description exists
        if not finding.get("Description"):
            finding["Description"] = (
                finding.get("Recommendation") or
                finding.get("Status") or
                finding.get("Header") or
                finding.get("Name") or
                "No description available"
            )
        
        normalized.append(finding)
    
    return normalized


# Add this to the compute_cvss_overrides_from_findings() function in findings_summary.py
# Add it right after the HTTP Method logic

def compute_cvss_overrides_from_findings(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, str]]:
    """
    Compute dynamic CVSS overrides for categories with conditional severity/CVSS.
    
    Handles:
    - HTTP Methods: Low (3.7) if only OPTIONS, Medium (5.3) otherwise
    - SSL/TLS: High (9.8) if HTTPS not supported, Medium (5.3) otherwise
    - Path Traversal: High (7.5) if direct evidence, Medium (5.3) otherwise
    """
    overrides = {}
    
    # Group findings by category
    by_category = defaultdict(list)
    for f in findings:
        cat = f.get("Category", "Unknown")
        by_category[cat].append(f)
    
    # --- HTTP Method Dynamic Logic ---
    if "HTTP Method" in by_category or "HTTP Methods" in by_category:
        http_findings = by_category.get("HTTP Method", []) or by_category.get("HTTP Methods", [])
        
        methods = []
        for f in http_findings:
            method = f.get("Method", "") or f.get("_item_short", "")
            if method:
                method_clean = method.upper()
                if ":" in method_clean:
                    method_clean = method_clean.split(":", 1)[1].strip()
                methods.append(method_clean)
        
        # Use the category name that actually exists in findings
        category_key = "HTTP Methods" if "HTTP Methods" in by_category else "HTTP Method"
        
        if set(methods) == {"OPTIONS"}:
            overrides[category_key] = {
                "severity": "Low",
                "cvss": "3.7",
                "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
            }
        else:
            overrides[category_key] = {
                "severity": "Medium",
                "cvss": "5.3",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            }
    
    # --- SSL/TLS Dynamic Logic ---
    if "SSL/TLS" in by_category:
        ssl_findings = by_category["SSL/TLS"]
        
        has_https_not_supported = any(
            "HTTPS Not Supported" in f.get("Description", "")
            or "HTTPS not supported" in f.get("Description", "")
            or "HTTPS Not Supported" in f.get("Title", "")
            or "No TLS listener" in f.get("Current Value", "")
            or "No TLS listener" in f.get("Evidence", "")
            or "No TLS listener" in f.get("CurrentValue", "")
            for f in ssl_findings
        )
        
        if has_https_not_supported:
            overrides["SSL/TLS"] = {
                "severity": "High",
                "cvss": "9.8",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
        else:
            overrides["SSL/TLS"] = {
                "severity": "Medium",
                "cvss": "5.3",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            }
    
    # --- Path Traversal Dynamic Logic ---
    if "Path Traversal" in by_category:
        pt_findings = by_category["Path Traversal"]
        
        has_direct_evidence = any(
            "Direct evidence" in (f.get("Behavior") or "")
            or "Direct evidence" in (f.get("Evidence") or "")
            for f in pt_findings
        )
        
        if has_direct_evidence:
            overrides["Path Traversal"] = {
                "severity": "High",
                "cvss": "7.5",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            }
        else:
            overrides["Path Traversal"] = {
                "severity": "Medium",
                "cvss": "5.3",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            }
    
    # --- NEW: Directory Exposure Dynamic Logic ---
    # The directory_scan.py module already computes severity dynamically
    # We extract it from the findings and use that
    if "Directory Exposure" in by_category:
        dir_findings = by_category["Directory Exposure"]
        
        if dir_findings:
            # Import the helper from directory_scan module
            from websecscan.directory_scan import _severity_for, _cvss_for, _overall_severity
            
            # Use the scanner's own logic to determine severity
            overall_sev = _overall_severity(dir_findings)
            overall_cvss = _cvss_for(overall_sev)
            
            # Extract just the numeric score (e.g., "8.2" from "8.2 (AV:N/AC:L...)")
            cvss_num = overall_cvss.split()[0] if overall_cvss else "8.2"
            
            overrides["Directory Exposure"] = {
                "severity": overall_sev,
                "cvss": cvss_num,
                "cvss_vector": overall_cvss.split("(")[1].rstrip(")") if "(" in overall_cvss else ""
            }
    
    return overrides


def print_summary_table(
    summary: Dict[str, Dict[str, any]],
    title: str = "Security Findings Summary",
):
    """
    Print a clean, tidy summary table.
    Columns:
    Category | Severity | CVSS Score | Number of Findings
    """

    if not summary:
        print(Fore.GREEN + f"\n{title}")
        print("=" * 120)
        print("✅ No security findings detected.")
        print("=" * 120 + "\n")
        return

    print(Fore.CYAN + f"\n{title}")
    print("=" * 120)

    # Table header (ONLY 4 COLUMNS)
    print(
        f"{Fore.WHITE}"
        f"{'Category':<70} "
        f"{'Severity':<10} "
        f"{'CVSS Score':<13} "
        f"{'Number of Findings':<20}"
    )
    print("-" * 120)

    severity_rank = {"High": 3, "Medium": 2, "Low": 1}

    # Sort by severity then by finding count
    sorted_items = sorted(
        summary.items(),
        key=lambda x: (severity_rank.get(x[1]["severity"], 0), x[1]["count"]),
        reverse=True
    )

    total_findings = 0
    has_high = False
    has_medium = False

    for category, data in sorted_items:
        severity = data["severity"]
        cvss = data["cvss"]
        count = data["count"]
        display_name = data.get("display_name", category)

        total_findings += count

        if severity == "High":
            sev_color = Fore.RED
            has_high = True
        elif severity == "Medium":
            sev_color = Fore.YELLOW
            has_medium = True
        else:
            sev_color = Fore.GREEN

        print(
            f"{sev_color}{display_name:<70}{Style.RESET_ALL} "
            f"{sev_color}{severity:<10}{Style.RESET_ALL} "
            f"{sev_color}{cvss:<13}{Style.RESET_ALL} "
            f"{Fore.WHITE}{count:<20}{Style.RESET_ALL}"
        )

    print("-" * 120)

    # Overall severity
    if has_high:
        overall_severity = "High"
        overall_color = Fore.RED
    elif has_medium:
        overall_severity = "Medium"
        overall_color = Fore.YELLOW
    else:
        overall_severity = "Low"
        overall_color = Fore.GREEN

    # Overall row (INCLUDES TOTAL FINDINGS)
    print(
        f"{Fore.CYAN}{'Overall':<70}{Style.RESET_ALL} "
        f"{overall_color}{overall_severity:<10}{Style.RESET_ALL} "
        f"{Fore.WHITE}{'—':<13}{Style.RESET_ALL} "
        f"{Fore.WHITE}{total_findings:<20}{Style.RESET_ALL}"
    )

    print("=" * 120 + "\n")