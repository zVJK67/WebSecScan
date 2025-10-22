'''
from colorama import Fore, Style

def print_summary(header_findings, method_findings, cookie_findings):
    """
    Print a compact summary table with counts by severity and an overall risk level.
    Includes header, method, and cookie analysis findings.
    """
    all_findings = list(header_findings) + list(method_findings) + list(cookie_findings)

    # Counts by severity
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in all_findings:
        sev = f.get("Severity")
        if sev in counts:
            counts[sev] += 1

    total = sum(counts.values())

    # Overall risk: HIGH if any High, MEDIUM if no High but >=2 Medium, else LOW
    if counts["High"] > 0:
        overall = "HIGH"
    elif counts["Medium"] >= 2:
        overall = "MEDIUM"
    else:
        overall = "LOW"

    # Print table
    print("\n" + Fore.MAGENTA + "==================== Summary ====================" + Style.RESET_ALL)
    print(Fore.WHITE + f"Total Issues: {Fore.YELLOW}{total}{Style.RESET_ALL}")
    print(Fore.RED + f"High Severity: {counts['High']}" + Style.RESET_ALL + " | " +
          Fore.YELLOW + f"Medium: {counts['Medium']}" + Style.RESET_ALL + " | " +
          Fore.GREEN + f"Low: {counts['Low']}" + Style.RESET_ALL)
    print(Fore.WHITE + "Overall Risk: " + (
        Fore.RED if overall == "HIGH" else
        (Fore.YELLOW if overall == "MEDIUM" else Fore.GREEN)
    ) + f"{overall}" + Style.RESET_ALL)
    print(Fore.MAGENTA + "=================================================" + Style.RESET_ALL)
'''

from colorama import Fore, Style

def print_summary(header_findings, method_findings, other_findings):
    """
    Print a compact summary table with counts by severity and an overall risk level.
    Includes header, method, cookie, CORS, and SSL/TLS analysis findings.
    """

    # Combine all findings
    all_findings = list(header_findings) + list(method_findings) + list(other_findings)

    # Initialize severity counters
    counts = {"High": 0, "Medium": 0, "Low": 0}

    # Optional: category counters
    category_counts = {
        "Headers": len(header_findings),
        "HTTP Methods": len(method_findings),
        "Other": len(other_findings)
    }

    # Count severities
    for f in all_findings:
        sev = f.get("Severity")
        if sev in counts:
            counts[sev] += 1

    total = sum(counts.values())

    # Determine overall risk
    if counts["High"] > 0:
        overall = "HIGH"
        color = Fore.RED
    elif counts["Medium"] >= 2:
        overall = "MEDIUM"
        color = Fore.YELLOW
    else:
        overall = "LOW"
        color = Fore.GREEN

    # Print summary header
    print("\n" + Fore.MAGENTA + "==================== Summary ====================" + Style.RESET_ALL)
    print(Fore.WHITE + f"Total Issues: {Fore.YELLOW}{total}{Style.RESET_ALL}")
    print(Fore.RED + f"High: {counts['High']}" + Style.RESET_ALL + " | " +
          Fore.YELLOW + f"Medium: {counts['Medium']}" + Style.RESET_ALL + " | " +
          Fore.GREEN + f"Low: {counts['Low']}" + Style.RESET_ALL)

    # Print category breakdown (optional)
    print(Fore.WHITE + "\nBreakdown by Category:" + Style.RESET_ALL)
    print(f"  Headers: {category_counts['Headers']} findings")
    print(f"  HTTP Methods: {category_counts['HTTP Methods']} findings")
    print(f"  Other (Cookies / CORS / SSL): {category_counts['Other']} findings")

    # Print overall risk
    print(Fore.WHITE + "\nOverall Risk: " + color + f"{overall}" + Style.RESET_ALL)
    print(Fore.MAGENTA + "=================================================" + Style.RESET_ALL)
