from typing import List, Dict, Any, Tuple
from colorama import Fore, Style
from tabulate import tabulate


def _overall_risk_level(counts: Dict[str, int]) -> Tuple[str, str]:
    """Decide overall risk string and color."""
    if counts.get("High", 0) > 0:
        return "HIGH", Fore.RED
    if counts.get("Medium", 0) >= 2:
        return "MEDIUM", Fore.YELLOW
    return "LOW", Fore.GREEN


def summarize_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize total counts by severity and category."""
    counts = {"High": 0, "Medium": 0, "Low": 0}
    category_matrix: Dict[str, Dict[str, int]] = {}
    total = 0

    for f in findings:
        sev = f.get("Severity", "Low")
        if sev not in counts:
            sev = "Low"
        counts[sev] += 1
        cat = f.get("Category", "Other")
        if cat not in category_matrix:
            category_matrix[cat] = {"High": 0, "Medium": 0, "Low": 0}
        category_matrix[cat][sev] += 1
        total += 1

    overall, color = _overall_risk_level(counts)
    return {
        "total_findings": total,
        "counts": counts,
        "category_matrix": category_matrix,
        "overall_risk": overall,
        "overall_color": color
    }


def print_summary(header_findings: List[Dict[str, Any]],
                  method_findings: List[Dict[str, Any]],
                  other_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Print a clear, wide summary table using 'tabulate'.
    """
    all_findings = list(header_findings or []) + list(method_findings or []) + list(other_findings or [])
    summary = summarize_findings(all_findings)

    total = summary["total_findings"]
    counts = summary["counts"]
    matrix = summary["category_matrix"]
    overall = summary["overall_risk"]
    color = summary["overall_color"]

    print("\n" + Fore.MAGENTA + "====================== Findings Summary ======================" + Style.RESET_ALL)
    print(Fore.WHITE + f"Total Issues: {Fore.YELLOW}{total}{Style.RESET_ALL}")
    print(Fore.RED + f"High: {counts['High']}" + Style.RESET_ALL + " | " +
          Fore.YELLOW + f"Medium: {counts['Medium']}" + Style.RESET_ALL + " | " +
          Fore.GREEN + f"Low: {counts['Low']}" + Style.RESET_ALL)
    print(Fore.MAGENTA + "===============================================================" + Style.RESET_ALL)

    # Build table data
    table_data = []
    for cat, sev_counts in sorted(matrix.items(), key=lambda x: (-x[1].get("High", 0), -sum(x[1].values()), x[0])):
        total_cat = sum(sev_counts.values())
        table_data.append([
            cat,
            sev_counts.get("High", 0),
            sev_counts.get("Medium", 0),
            sev_counts.get("Low", 0),
            total_cat
        ])

    # Print pretty table
    if table_data:
        print(Fore.WHITE + "\nBreakdown by Category (Severity Counts):" + Style.RESET_ALL)
        print(tabulate(
            table_data,
            headers=[Fore.CYAN + "Category" + Style.RESET_ALL,
                     Fore.RED + "High" + Style.RESET_ALL,
                     Fore.YELLOW + "Medium" + Style.RESET_ALL,
                     Fore.GREEN + "Low" + Style.RESET_ALL,
                     Fore.WHITE + "Total" + Style.RESET_ALL],
            tablefmt="grid",
            numalign="center",
            stralign="center"
        ))
    else:
        print(Fore.YELLOW + "No findings to summarize." + Style.RESET_ALL)

    print(Fore.WHITE + "\nOverall Risk: " + color + f"{overall}" + Style.RESET_ALL)
    print(Fore.MAGENTA + "===============================================================" + Style.RESET_ALL)

    return summary
