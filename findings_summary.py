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
    print_summary_table(summary)
"""

from typing import List, Dict, Any
from collections import defaultdict
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


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
        if not finding.get("Severity"):
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


def generate_summary(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """
    Generate a summary of findings grouped by category with severity counts.
    
    Args:
        findings: List of finding dictionaries with 'Category' and 'Severity' keys
        
    Returns:
        Dictionary mapping category names to severity counts
        Example: {'CORS': {'High': 2, 'Medium': 1, 'Low': 0}, ...}
    """
    summary = defaultdict(lambda: {"High": 0, "Medium": 0, "Low": 0})
    
    for finding in findings:
        category = finding.get("Category", "Unknown")
        severity = finding.get("Severity", "Low")
        
        # Normalize severity to handle case variations
        severity = severity.strip().capitalize()
        
        if severity in ["High", "Medium", "Low"]:
            summary[category][severity] += 1
        else:
            # If severity is invalid, count as Low
            summary[category]["Low"] += 1
    
    return dict(summary)


def calculate_category_score(counts: Dict[str, int]) -> int:
    """
    Calculate a score for sorting categories by severity.
    Higher score = more severe issues.
    
    Args:
        counts: Dictionary with High/Medium/Low counts
        
    Returns:
        Integer score (High=100, Medium=10, Low=1)
    """
    return (counts.get("High", 0) * 100 + 
            counts.get("Medium", 0) * 10 + 
            counts.get("Low", 0) * 1)


def print_summary_table(summary: Dict[str, Dict[str, int]], title: str = "Security Findings Summary"):
    """
    Print a formatted summary table ordered by severity (highest first).
    
    Args:
        summary: Dictionary from generate_summary()
        title: Optional title for the table
    """
    if not summary:
        print(Fore.GREEN + f"\n{title}")
        print("=" * 80)
        print("✅ No security findings detected.")
        print("=" * 80 + "\n")
        return
    
    # Sort categories by severity score (highest first)
    sorted_categories = sorted(
        summary.items(),
        key=lambda x: calculate_category_score(x[1]),
        reverse=True
    )
    
    # Calculate totals
    total_high = sum(counts["High"] for _, counts in sorted_categories)
    total_medium = sum(counts["Medium"] for _, counts in sorted_categories)
    total_low = sum(counts["Low"] for _, counts in sorted_categories)
    total_findings = total_high + total_medium + total_low
    
    # Print header
    print(Fore.CYAN + f"\n{title}")
    print("=" * 80)
    print(Fore.WHITE + f"Total Findings: {total_findings} | " +
          Fore.RED + f"High: {total_high} " +
          Fore.YELLOW + f"Medium: {total_medium} " +
          Fore.GREEN + f"Low: {total_low}")
    print("=" * 80 + "\n")
    
    # Table header
    print(f"{Fore.WHITE}{'Category':<35} {'High':>10} {'Medium':>10} {'Low':>10} {'Total':>10}")
    print("-" * 80)
    
    # Print each category
    for category, counts in sorted_categories:
        high = counts["High"]
        medium = counts["Medium"]
        low = counts["Low"]
        total = high + medium + low
        
        # Color code the category name based on highest severity
        if high > 0:
            category_color = Fore.RED
        elif medium > 0:
            category_color = Fore.YELLOW
        else:
            category_color = Fore.GREEN
        
        print(f"{category_color}{category:<35}{Style.RESET_ALL} " +
              f"{Fore.RED if high > 0 else Fore.WHITE}{high:>10}{Style.RESET_ALL} " +
              f"{Fore.YELLOW if medium > 0 else Fore.WHITE}{medium:>10}{Style.RESET_ALL} " +
              f"{Fore.GREEN if low > 0 else Fore.WHITE}{low:>10}{Style.RESET_ALL} " +
              f"{Fore.WHITE}{total:>10}{Style.RESET_ALL}")
    
    # Print totals row
    print("-" * 80)
    print(f"{Fore.CYAN}{'TOTAL':<35}{Style.RESET_ALL} " +
          f"{Fore.RED}{total_high:>10}{Style.RESET_ALL} " +
          f"{Fore.YELLOW}{total_medium:>10}{Style.RESET_ALL} " +
          f"{Fore.GREEN}{total_low:>10}{Style.RESET_ALL} " +
          f"{Fore.CYAN}{total_findings:>10}{Style.RESET_ALL}")
    print("=" * 80 + "\n")


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


def export_summary_csv(summary: Dict[str, Dict[str, int]], filename: str = "security_findings_summary.csv"):
    """
    Export the summary table to a CSV file.
    
    Args:
        summary: Dictionary from generate_summary()
        filename: Output CSV filename
    """
    import csv
    
    # Sort categories by severity
    sorted_categories = sorted(
        summary.items(),
        key=lambda x: calculate_category_score(x[1]),
        reverse=True
    )
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Category', 'High', 'Medium', 'Low', 'Total'])
        
        total_high = 0
        total_medium = 0
        total_low = 0
        
        for category, counts in sorted_categories:
            high = counts["High"]
            medium = counts["Medium"]
            low = counts["Low"]
            total = high + medium + low
            
            writer.writerow([category, high, medium, low, total])
            
            total_high += high
            total_medium += medium
            total_low += low
        
        # Write totals
        writer.writerow(['TOTAL', total_high, total_medium, total_low, 
                        total_high + total_medium + total_low])
    
    print(Fore.GREEN + f"✅ Summary exported to {filename}\n" + Style.RESET_ALL)

