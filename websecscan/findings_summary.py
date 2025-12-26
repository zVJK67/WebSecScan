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
CATEGORY_CVSS_MAP = {
    "Security Headers": {
        "severity": "Low",
        "cvss": "3.1",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    },
    "HTTP Method": {
        "severity": "Medium",  # Default, can be overridden
        "cvss": "5.3",  # Default, can be overridden
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
        "severity": "Medium",
        "cvss": "5.3",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "Path Traversal": {
        "severity": "High",
        "cvss": "7.5",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    "SSL/TLS": {
        "severity": "Medium",  # Default, can be overridden
        "cvss": "5.3",  # Default, can be overridden
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
    Compute dynamic CVSS overrides for categories that have conditional severity/CVSS.
    Currently handles:
    - HTTP Method: Low (3.7) if only OPTIONS, Medium (5.3) otherwise
    - SSL/TLS: High (9.8) if HTTPS not supported, Medium (5.3) otherwise
    
    Args:
        findings: List of all findings
        
    Returns:
        Dictionary mapping category names to {severity, cvss, cvss_vector}
    """
    overrides = {}
    
    # Group findings by category
    by_category = defaultdict(list)
    for f in findings:
        cat = f.get("Category", "Unknown")
        by_category[cat].append(f)
    
    # --- HTTP Method Dynamic Logic ---
    if "HTTP Method" in by_category:
        http_findings = by_category["HTTP Method"]
        # Check if only OPTIONS method is unsafe
        methods = []
        for f in http_findings:
            method = f.get("Method", "")
            if method:
                methods.append(method.upper())
        
        # If only OPTIONS is present, use Low severity
        if set(methods) == {"OPTIONS"}:
            overrides["HTTP Method"] = {
                "severity": "Low",
                "cvss": "3.7",
                "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
            }
        else:
            # Default Medium severity
            overrides["HTTP Method"] = {
                "severity": "Medium",
                "cvss": "5.3",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            }
    
    # --- SSL/TLS Dynamic Logic (NEW) ---
    if "SSL/TLS" in by_category:
        ssl_findings = by_category["SSL/TLS"]
        
        # Check if "HTTPS Not Supported" is present
        has_https_not_supported = any(
            "HTTPS Not Supported" in f.get("Description", "")
            or "HTTPS not supported" in f.get("Description", "")
            or "No TLS listener" in f.get("Current Value", "")
            or "No TLS listener" in f.get("Evidence", "")
            or "No TLS listener" in f.get("CurrentValue", "")
            for f in ssl_findings
        )
        
        if has_https_not_supported:
            # High severity ONLY for HTTPS not supported
            overrides["SSL/TLS"] = {
                "severity": "High",
                "cvss": "9.8",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
        else:
            # Default Medium severity for all other SSL/TLS issues
            overrides["SSL/TLS"] = {
                "severity": "Medium",
                "cvss": "5.3",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            }
    
    return overrides


def generate_summary(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """
    Generate a summary of findings grouped by category with counts.
    Note: This now just counts findings per category (no severity breakdown).
    
    Args:
        findings: List of finding dictionaries with 'Category' keys
        
    Returns:
        Dictionary mapping category names to finding counts
        Example: {'CORS Security': {'count': 3}, 'Security Headers': {'count': 11}, ...}
    """
    summary = defaultdict(lambda: {"count": 0})
    
    for finding in findings:
        category = finding.get("Category", "Unknown")
        summary[category]["count"] += 1
    
    return dict(summary)


def calculate_category_score(category: str, count: int, cvss_map: Dict[str, Dict[str, str]]) -> int:
    # Normalize category name so it matches CATEGORY_CVSS_MAP keys
    category = normalize_category_for_cvss(category)

    severity = cvss_map.get(category, {}).get("severity", "Low")

    severity_weights = {
        "High": 100,
        "Medium": 10,
        "Low": 1
    }

    weight = severity_weights.get(severity, 1)
    return weight * count


def print_summary_table(summary: Dict[str, Dict[str, int]], title: str = "Security Findings Summary", cvss_overrides: Dict[str, Dict[str, str]] = None):
    """
    Print a formatted summary table matching the new design:
    Category | Severity | CVSS Score | Number of Findings | Status
    
    Args:
        summary: Dictionary from generate_summary()
        title: Optional title for the table
        cvss_overrides: Optional dictionary of dynamic CVSS overrides from compute_cvss_overrides_from_findings()
    """
    if not summary:
        print(Fore.GREEN + f"\n{title}")
        print("=" * 120)
        print("✅ No security findings detected.")
        print("=" * 120 + "\n")
        return
    
    # Merge predefined CVSS with overrides
    cvss_map = CATEGORY_CVSS_MAP.copy()
    if cvss_overrides:
        for cat, override in cvss_overrides.items():
            if cat in cvss_map:
                cvss_map[cat].update(override)
    
    # Sort categories by severity score (highest first)
    sorted_categories = sorted(
        summary.items(),
        key=lambda x: calculate_category_score(x[0], x[1]["count"], cvss_map),
        reverse=True
    )
    
    # Calculate totals
    total_findings = sum(counts["count"] for _, counts in sorted_categories)
    
    # Print header
    print(Fore.CYAN + f"\n{title}")
    print("=" * 120)
    print(Fore.WHITE + f"Total Findings: {total_findings}")
    print("=" * 120 + "\n")
    
    # Table header
    print(f"{Fore.WHITE}{'Category':<40} {'Severity':<12} {'CVSS Score':<20} {'Number of Findings':<22} {'Status':<20}")
    print("-" * 120)
    
    # Print each category
    for category, counts in sorted_categories:
        finding_count = counts["count"]
        
        # Get CVSS info for this category
        cvss_key = normalize_category_for_cvss(category)
        cvss_info = cvss_map.get(cvss_key, {
            "severity": "Low",
            "cvss": "N/A",
            "cvss_vector": ""
        })
        
        # Prefer dynamic severity if findings exist
        severity = cvss_info.get("severity", "Low")
        if summary.get(category, {}).get("count", 0) > 0:
            # trust findings severity when available
            severity = cvss_overrides.get(cvss_key, {}).get("severity", severity)

        cvss = cvss_info.get("cvss", "N/A")
        
        # Determine status
        status = "✗ Issues found" if finding_count > 0 else "✓ No issues"
        
        # Color code based on severity
        if severity == "High":
            severity_color = Fore.RED
            category_color = Fore.RED
        elif severity == "Medium":
            severity_color = Fore.YELLOW
            category_color = Fore.YELLOW
        else:
            severity_color = Fore.GREEN
            category_color = Fore.GREEN
        
        # Status color
        status_color = Fore.RED if finding_count > 0 else Fore.GREEN
        
        # Format finding count
        finding_text = f"{finding_count} finding{'s' if finding_count != 1 else ''}"
        
        print(f"{category_color}{category:<40}{Style.RESET_ALL} "
              f"{severity_color}{severity:<12}{Style.RESET_ALL} "
              f"{Fore.WHITE}{cvss:<20}{Style.RESET_ALL} "
              f"{Fore.WHITE}{finding_text:<22}{Style.RESET_ALL} "
              f"{status_color}{status:<20}{Style.RESET_ALL}")
    
    # Add "Overall" row
    print("-" * 120)
    
    # Determine overall severity
    has_high = False
    has_medium = False

    for cat, data in summary.items():
        if data.get("count", 0) <= 0:
            continue

        key = normalize_category_for_cvss(cat)

        sev = cvss_overrides.get(key, {}).get(
            "severity",
            cvss_map.get(key, {}).get("severity")
        )

        if sev == "High":
            has_high = True
        elif sev == "Medium":
            has_medium = True

    
    if has_high:
        overall_severity = "High"
        overall_color = Fore.RED
    elif has_medium:
        overall_severity = "Medium"
        overall_color = Fore.YELLOW
    else:
        overall_severity = "Low"
        overall_color = Fore.GREEN
    
    overall_status = "⚠ Security weaknesses detected"
    overall_status_color = Fore.YELLOW
    
    print(f"{Fore.CYAN}{'Overall':<40}{Style.RESET_ALL} "
          f"{overall_color}{overall_severity:<12}{Style.RESET_ALL} "
          f"{Fore.WHITE}{'—':<20}{Style.RESET_ALL} "
          f"{Fore.WHITE}{'—':<22}{Style.RESET_ALL} "
          f"{overall_status_color}{overall_status:<20}{Style.RESET_ALL}")
    
    print("=" * 120 + "\n")


def print_detailed_findings(findings: List[Dict[str, Any]], category_filter: str = None):
    """
    Print detailed findings, optionally filtered by category.
    
    Args:
        findings: List of finding dictionaries
        category_filter: Optional category name to filter by
    """
    if category_filter:
        findings = [f for f in findings if f.get("Category") == category_filter]
        print(Fore.CYAN + f"\nDetailed Findings for: {category_filter}")
    else:
        print(Fore.CYAN + "\nDetailed Findings (All Categories)")
    
    print("=" * 80 + "\n")
    
    if not findings:
        print(Fore.GREEN + "No findings to display.\n")
        return
    
    # Sort by severity
    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    sorted_findings = sorted(
        findings,
        key=lambda f: (severity_order.get(f.get("Severity", "Low"), 3), f.get("Category", ""))
    )
    
    for idx, finding in enumerate(sorted_findings, 1):
        severity = finding.get("Severity", "Low")
        category = finding.get("Category", "Unknown")
        description = finding.get("Description", "No description")
        
        # Color based on severity
        sev_color = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.GREEN}.get(severity, Fore.WHITE)
        
        print(f"{Fore.WHITE}{idx}. [{category}]{Style.RESET_ALL}")
        print(f"   Severity: {sev_color}{severity}{Style.RESET_ALL}")
        print(f"   {description}")
        
        # Print additional context if available
        if "URL" in finding and finding["URL"]:
            print(f"   URL: {finding['URL']}")
        if "Context" in finding and finding["Context"]:
            print(f"   Context: {finding['Context']}")
        if "Recommendation" in finding and finding["Recommendation"]:
            print(f"   {Fore.CYAN}→ {finding['Recommendation']}{Style.RESET_ALL}")
        
        print()


def export_summary_csv(summary: Dict[str, Dict[str, int]], filename: str = "security_findings_summary.csv", cvss_overrides: Dict[str, Dict[str, str]] = None):
    """
    Export the summary table to a CSV file.
    
    Args:
        summary: Dictionary from generate_summary()
        filename: Output CSV filename
        cvss_overrides: Optional dictionary of dynamic CVSS overrides
    """
    import csv
    
    # Merge predefined CVSS with overrides
    cvss_map = CATEGORY_CVSS_MAP.copy()
    if cvss_overrides:
        for cat, override in cvss_overrides.items():
            if cat in cvss_map:
                cvss_map[cat].update(override)
    
    # Sort categories by severity
    sorted_categories = sorted(
        summary.items(),
        key=lambda x: calculate_category_score(x[0], x[1]["count"], cvss_map),
        reverse=True
    )
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Category', 'Severity', 'CVSS Score', 'Number of Findings', 'Status'])
        
        for category, counts in sorted_categories:
            finding_count = counts["count"]
            cvss_info = cvss_map.get(category, {"severity": "Low", "cvss": "N/A"})
            severity = cvss_info.get("severity", "Low")
            cvss = cvss_info.get("cvss", "N/A")
            status = "Issues found" if finding_count > 0 else "No issues"
            
            writer.writerow([category, severity, cvss, finding_count, status])
        
        # Overall row
        has_high = any(cvss_map.get(cat, {}).get("severity") == "High" and summary.get(cat, {}).get("count", 0) > 0 
                       for cat in summary.keys())
        has_medium = any(cvss_map.get(cat, {}).get("severity") == "Medium" and summary.get(cat, {}).get("count", 0) > 0 
                         for cat in summary.keys())
        
        if has_high:
            overall_severity = "High"
        elif has_medium:
            overall_severity = "Medium"
        else:
            overall_severity = "Low"
        
        writer.writerow(['Overall', overall_severity, '—', '—', 'Security weaknesses detected'])
    
    print(Fore.GREEN + f"✅ Summary exported to {filename}\n" + Style.RESET_ALL)