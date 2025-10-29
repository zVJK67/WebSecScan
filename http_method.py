from typing import List, Union, Dict, Any
from colorama import Fore, Style

def analyze_http_methods(methods: Union[List[str], str, None]) -> List[Dict[str, Any]]:
    """
    Analyze allowed HTTP methods and report their associated security risks.

    - methods: list of method names (e.g. ['GET','POST']) or a comma-separated string from an Allow header.
    - returns: list of finding dicts.
    """
    if not methods:
        return [{
            "Header": "HTTP Methods",
            "Status": "Unknown",
            "Severity": "Medium",
            "Recommendation": "Server did not advertise allowed methods. Try an OPTIONS request or manual testing."
        }]

    # Normalize input to a deduplicated uppercase list
    if isinstance(methods, str):
        methods_list = [m.strip().upper() for m in methods.split(",") if m.strip()]
    else:
        methods_list = [str(m).strip().upper() for m in methods if str(m).strip()]

    methods_list = sorted(list(dict.fromkeys(methods_list)))  # deduplicate while preserving order-ish

    # Known risky HTTP methods and their security risks
    method_risks = {
        "PUT": "Can allow attackers to upload or overwrite files on the server.",
        "DELETE": "Can allow attackers to delete resources or content on the server.",
        "TRACE": "Can be used in cross-site tracing (XST) attacks to expose sensitive data; disable unless needed for diagnostics.",
        "CONNECT": "Can enable tunneling to internal network resources (rarely needed on public web servers).",
        "PATCH": "Can modify data on the server if not properly controlled.",
        # WebDAV / other methods often exposed by mistake
        "PROPFIND": "WebDAV method that can leak file system structure or metadata.",
        "MKCOL": "WebDAV method to create collections (dirs); may allow unwanted resource creation.",
        "LOCK": "WebDAV locking method; can be abused in some setups.",
        "UNLOCK": "WebDAV unlock method.",
        "REPORT": "WebDAV/report method; can expose repository information.",
        "COPY": "Can copy resources on the server if misconfigured.",
        "MOVE": "Can move/rename resources; risky if not intended.",
    }

    findings: List[Dict[str, Any]] = []
    risky_methods = [m for m in methods_list if m in method_risks]

    if risky_methods:
        for method in risky_methods:
            findings.append({
                "Header": f"HTTP Method: {method}",
                "Status": "Unsafe",
                "Severity": "High",
                "Recommendation": f"Disable or restrict '{method}' — {method_risks[method]}"
            })
    else:
        findings.append({
            "Header": "HTTP Methods",
            "Status": "Safe",
            "Severity": "Low",
            "Recommendation": "No commonly unsafe HTTP methods detected. Typical safe methods: GET, POST, HEAD, OPTIONS."
        })

    return findings


def print_http_method_findings(findings: List[Dict[str, Any]], methods: Union[List[str], str, None]) -> None:
    """
    Display HTTP method security analysis results with allowed methods and unsafe summary.
    """
    print("\n" + Fore.CYAN + "🔒 HTTP Method Security Check" + Style.RESET_ALL)
    print(Fore.CYAN + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

    # Prepare methods display
    if not methods:
        methods_display = "(None or not advertised)"
    elif isinstance(methods, str):
        methods_display = methods
    else:
        methods_display = ", ".join([str(m).upper() for m in methods])

    print(Fore.YELLOW + f"Allowed Methods: {methods_display}" + Style.RESET_ALL)

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
            }.get(f.get("Severity", "Low"), Fore.WHITE)

            # print method title without repeating "HTTP Method:"
            header_title = f.get('Header', '').replace("HTTP Method: ", "")
            print(f"{Fore.WHITE}{i}. {header_title} — {f.get('Status', '')}")
            print(f"   {severity_color}Severity: {f.get('Severity', '')}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}   Recommendation: {f.get('Recommendation', '')}\n")

        # Print safe methods note
        print(Fore.GREEN + "✅ Safe methods (GET, POST, HEAD, OPTIONS) are acceptable for normal web applications.\n" + Style.RESET_ALL)

    # bottom divider
    print(Fore.CYAN + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
