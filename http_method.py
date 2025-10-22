from colorama import Fore, Style

def analyze_http_methods(methods):
    findings = []
    
    """
    Analyze allowed HTTP methods and report their associated security risks.
    """
    if not methods:
        return [{
            "Header": "HTTP Methods",
            "Status": "Unknown",
            "Severity": "Medium",
            "Recommendation": "Server did not respond with an Allow header. Test manually using OPTIONS request."
        }]

    # Known risky HTTP methods and their security risks
    method_risks = {
        "PUT": "Can allow attackers to upload or overwrite files on the server.",
        "DELETE": "Can allow attackers to delete resources or content on the server.",
        "TRACE": "Can be used in cross-site tracing (XST) attacks to steal authentication data.",
        "CONNECT": "Can enable tunneling to internal network resources.",
        "PATCH": "Can modify data on the server if not properly controlled.",
    }

    findings = []
    risky_methods = [m for m in methods if m.upper() in method_risks]

    if risky_methods:
        for method in risky_methods:
            findings.append({
                "Header": f"HTTP Method: {method}",
                "Status": "Unsafe",
                "Severity": "High",
                "Recommendation": f"Disable or restrict '{method}' — {method_risks[method.upper()]}"
            })
    else:
        findings.append({
            "Header": "HTTP Methods",
            "Status": "Safe",
            "Severity": "Low",
            "Recommendation": "No unsafe HTTP methods detected. Common safe methods are GET, POST, HEAD, OPTIONS."
        })

    return findings

def print_http_method_findings(findings, methods):
    """
    Display HTTP method security analysis results with allowed methods and unsafe summary.
    """
    print("\n" + Fore.CYAN + "🔒 HTTP Method Security Check" + Style.RESET_ALL)
    print(Fore.CYAN + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    # Show allowed methods first
    if methods:
        print(Fore.YELLOW + f"Allowed Methods: {', '.join(methods)}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "Allowed Methods: (None or not advertised)" + Style.RESET_ALL)

    unsafe_findings = [f for f in findings if f["Status"].lower() == "unsafe"]
    print(Fore.WHITE + f"Detected Unsafe Methods: {Fore.RED}{len(unsafe_findings)}{Style.RESET_ALL}\n")

    if not unsafe_findings:
        print(Fore.GREEN + "✅ No unsafe HTTP methods detected.\n" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "──────────────────────────────" + Style.RESET_ALL)
        for i, f in enumerate(unsafe_findings, 1):
            severity_color = {
                "High": Fore.RED,
                "Medium": Fore.YELLOW,
                "Low": Fore.GREEN
            }.get(f["Severity"], Fore.WHITE)

            # print method title without repeating "HTTP Method:"
            header_title = f['Header'].replace("HTTP Method: ", "")
            print(f"{Fore.WHITE}{i}. {header_title} — {f['Status']}")
            print(f"   {severity_color}Severity: {f['Severity']}")
            print(f"{Fore.CYAN}   Recommendation: {f['Recommendation']}\n")

        # Print safe methods note
        print(Fore.GREEN + "✅ Safe methods (GET, POST, HEAD, OPTIONS) are acceptable for normal web applications.\n" + Style.RESET_ALL)

    # bottom divider
    print(Fore.CYAN + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)