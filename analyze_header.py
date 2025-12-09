from colorama import Fore, Style

def analyze_security_headers(headers):
    findings = []

    # --- Content Security Policy (CSP) ---
    csp = headers.get("Content-Security-Policy")
    if not csp:
        findings.append({
            "Header": "Content-Security-Policy",
            "Status": "Missing",
            "Severity": "High",
            "Recommendation": "Add a CSP header to control sources of scripts, styles, and media."
        })
    else:
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            findings.append({
                "Header": "Content-Security-Policy",
                "Status": "Misconfigured",
                "Severity": "Medium",
                "Recommendation": "Avoid using 'unsafe-inline' or 'unsafe-eval' in CSP for stronger XSS protection."
            })
        else:
            findings.append({
                "Header": "Content-Security-Policy",
                "Status": "Present",
                "Severity": "Low",
                "Recommendation": "CSP implemented properly."
            })

    # --- Strict Transport Security (HSTS) ---
    if "Strict-Transport-Security" not in headers:
        findings.append({
            "Header": "Strict-Transport-Security",
            "Status": "Missing",
            "Severity": "High",
            "Recommendation": "Enable HSTS to enforce HTTPS and protect against downgrade attacks."
        })

    # --- X-Frame-Options ---
    xfo = headers.get("X-Frame-Options")
    if not xfo:
        findings.append({
            "Header": "X-Frame-Options",
            "Status": "Missing",
            "Severity": "Medium",
            "Recommendation": "Add X-Frame-Options: DENY to protect against clickjacking."
        })
    else:
        if xfo.strip().upper() != "DENY":
            findings.append({
                "Header": "X-Frame-Options",
                "Status": "Misconfigured",
                "Severity": "Medium",
                "Recommendation": "Set X-Frame-Options to DENY for maximum protection against clickjacking."
            })

    # --- X-XSS-Protection ---
    xxp = headers.get("X-XSS-Protection")
    if not xxp:
        findings.append({
            "Header": "X-XSS-Protection",
            "Status": "Missing",
            "Severity": "Medium",
            "Recommendation": "Add X-XSS-Protection: 1; mode=block for legacy browser XSS mitigation."
        })
    else:
        if xxp.strip() != "1; mode=block":
            findings.append({
                "Header": "X-XSS-Protection",
                "Status": "Misconfigured",
                "Severity": "Medium",
                "Recommendation": "Set X-XSS-Protection: 1; mode=block to enable basic XSS protection in older browsers."
            })

    # --- X-Content-Type-Options ---
    xcto = headers.get("X-Content-Type-Options")
    if not xcto:
        findings.append({
            "Header": "X-Content-Type-Options",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Add X-Content-Type-Options: nosniff to prevent MIME-type confusion."
        })
    else:
        if xcto.strip().lower() != "nosniff":
            findings.append({
                "Header": "X-Content-Type-Options",
                "Status": "Misconfigured",
                "Severity": "Low",
                "Recommendation": "Set X-Content-Type-Options: nosniff to prevent MIME-type confusion."
            })

    # --- Referrer Policy ---
    rp = headers.get("Referrer-Policy")
    if not rp:
        findings.append({
            "Header": "Referrer-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin to control referrer data leakage."
        })
    else:
        if rp.strip().lower() != "strict-origin-when-cross-origin":
            findings.append({
                "Header": "Referrer-Policy",
                "Status": "Misconfigured",
                "Severity": "Low",
                "Recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin to control referrer data leakage."
            })

    # --- Permissions Policy ---
    if "Permissions-Policy" not in headers:
        findings.append({
            "Header": "Permissions-Policy",
            "Status": "Missing",
            "Severity": "Low",
            "Recommendation": "Use Permissions-Policy to control access to browser features (e.g., camera, microphone)."
        })

    # --- Server header exposure ---
    if "Server" in headers:
        findings.append({
            "Header": "Server",
            "Status": "Misconfigured",
            "Severity": "Medium",
            "Recommendation": "Avoid exposing the Server header to reduce information disclosure."
        })

        # --- Allow header exposure ---
    if "Allow" in headers:
        findings.append({
            "Header": "Allow",
            "Status": "Misconfigured",
            "Severity": "Medium",
            "Recommendation": "Avoid exposing the 'Allow' header as it reveals supported HTTP methods."
        })

    return findings

def print_findings(findings):
    missing = [f for f in findings if f["Status"].lower() == "missing"]
    misconfigured = [f for f in findings if f["Status"].lower() == "misconfigured"]

    total_issues = len(missing) + len(misconfigured)

    # Top framing
    print("\n" + Fore.MAGENTA + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)
    print(Fore.CYAN + "🛡️ Security Header Analysis Results" + Style.RESET_ALL)
    print("════════════════════════════════════════════════════════════════")
    print(Fore.WHITE + f"Total Issues Detected: {Fore.YELLOW}{total_issues}{Style.RESET_ALL}")
    print(Fore.WHITE + f"Missing Headers: {Fore.RED}{len(missing)}{Style.RESET_ALL} | Misconfigured: {Fore.YELLOW}{len(misconfigured)}\n")

    def print_group(title, items, color):
        if not items:
            return
        print(color + f"{title}:" + Style.RESET_ALL)
        print(color + "────────────────────────" + Style.RESET_ALL)
        for i, f in enumerate(items, 1):
            severity_color = {
                "High": Fore.RED,
                "Medium": Fore.YELLOW,
                "Low": Fore.GREEN
            }.get(f["Severity"], Fore.WHITE)

            print(f"{Fore.WHITE}{i}. {f['Header']}")
            print(f"   {severity_color}Severity: {f['Severity']}")
            print(f"{Fore.CYAN}   Recommendation: {f['Recommendation']}\n")

    # Print groups
    print_group("🚫 Missing Headers", missing, Fore.RED)
    print_group("⚠️ Misconfigured Headers", misconfigured, Fore.YELLOW)

    if not missing and not misconfigured:
        print(Fore.GREEN + "\n✅ All security headers are properly configured!\n" + Style.RESET_ALL)

    # bottom framing
    print(Fore.MAGENTA + "════════════════════════════════════════════════════════════════" + Style.RESET_ALL)

def analyze_http_methods(methods):
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





    '''
# export_findings.py
"""
Export Findings Module

Exports security scan findings to HTML, JSON, and PDF formats.
Generates interactive HTML reports with client-side export functionality.
"""

import json
from typing import List, Dict, Any
from datetime import datetime
from colorama import Fore, Style

# dependency for templating
from jinja2 import Environment, select_autoescape, StrictUndefined

# Import vulnerability definitions for enrichment
try:
    from test3 import enrich_all_findings
except ImportError:
    # Fallback if vulnerability_definitions.py is not available
    def enrich_all_findings(findings):
        return findings


def export_to_json(findings: List[Dict[str, Any]], summary: Dict[str, Dict[str, int]],
                   filename: str = "security_scan_report.json", target_url: str = None) -> bool:
    """Export findings to a JSON file.""" 
    try:
        total_high = sum(counts.get("High", 0) for counts in summary.values())
        total_medium = sum(counts.get("Medium", 0) for counts in summary.values())
        total_low = sum(counts.get("Low", 0) for counts in summary.values())

        report = {
            "scan_metadata": {
                "target_url": target_url or "Unknown",
                "scan_time": datetime.now().isoformat(),
                "total_findings": len(findings),
                "severity_counts": {
                    "High": total_high,
                    "Medium": total_medium,
                    "Low": total_low
                }
            },
            "summary": summary,
            "findings": findings
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(Fore.GREEN + f"✅ JSON report exported to {filename}" + Style.RESET_ALL)
        return True

    except Exception as e:
        print(Fore.RED + f"[ERROR] Failed to export JSON: {e}" + Style.RESET_ALL)
        return False


# ---------------------------
# Embedded Jinja2 HTML template
# ---------------------------
REPORT_TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>WebSecScan Security Report</title>

  <!-- Chart.js CDN -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

  <style>
    /* Global reset */
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html,body { height:100%; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial;
      color: #203040;
      background: #f2f4f8;
      padding: 20px;
      -webkit-font-smoothing:antialiased;
    }

    /* A4 sizing for print and WeasyPrint */
    .page {
      width: 210mm;
      margin: 0 auto;
      background: white;
      border-radius: 6px;
      overflow: hidden;
      box-shadow: 0 8px 30px rgba(15,23,42,0.12);
    }

    /* Header */
    .report-header {
      background: linear-gradient(135deg,#ABE7B2 0%,#F7A5A5 100%);
      color: white;
      padding: 28px 32px;
    }
    .report-title { font-size: 28px; font-weight:800; margin-bottom:6px; }
    .report-sub { color: rgba(255,255,255,0.92); opacity:0.95; font-size:14px; }

    /* Meta */
    .meta {
      display:flex;
      gap:20px;
      padding:18px 32px;
      align-items:center;
      border-bottom: 1px solid #eef2fb;
    }
    .meta .meta-item { font-size:13px; color:#2f3a47; }
    .meta code { background:#eef3ff; padding:3px 6px; border-radius:4px; font-family:monospace; }

    /* Summary area */
    .summary {
      padding: 22px 32px 30px 32px;
      display:flex;
      gap:18px;
      align-items:flex-start;
      justify-content:flex-start;
    }
    /* left summary column width match screenshot */
    .left-summary { width: 560px; min-width:360px; }
    /* right summary is a fixed card */
    .right-summary { width: 360px; flex: 0 0 360px; margin-left:18px; }

    .stat-cards { display:flex; gap:12px; margin-bottom:14px; }
    .card {
      flex:1;
      background:linear-gradient(180deg,#fff 0,#FFF5F2 150%);
      border-radius:8px;
      padding:12px;
      border:1px solid #e7eefc;
      text-align:center;
    }
    .card .num { font-size:22px; font-weight:800; color:#243140; }
    .card .label { font-size:12px; color:#6b7280; margin-top:6px; text-transform:uppercase; letter-spacing:0.6px; }

    /* Table summary */
    table.summary-table { width:100%; border-collapse:collapse; margin-top:10px; background:#F9F8F6; }
    table.summary-table th, table.summary-table td {
      padding:10px 8px; text-align:center; border-bottom:1px solid #CBCBCB;
      font-size:13px;
    }
    table.summary-table th { background:#11224E; color:#CBDCEB; font-weight:700; font-size:12px; text-transform:uppercase; }
    table.summary-table tr:hover td { background:#EFE9E3; }

    /* Chart container (right card) */
    .chart-wrapper {
      background: #FFF0EF;
      border-radius: 12px;
      padding: 20px 18px;
      border: 2px solid rgba(0,0,0,0.08);
      display: flex;
      gap: 12px;
      align-items: center;
      justify-content: center;
      flex-direction: column;
      min-height: 420px;
      position: relative;
    }

    .chart-wrapper .card-title {
      font-size: 18px;
      font-weight: 800;
      color: #3f5f9a;
      text-align: center;
      margin-bottom: 12px;
    }

    /* Chart canvas container */
    .chart-container {
      position: relative;
      width: 320px;
      height: 320px;
    }

    #categoryChart {
      max-width: 100%;
      max-height: 100%;
    }

    /* Details */
    .details { padding: 24px 32px 40px; }
    .details h2 { font-size:20px; color:#243140; border-bottom:3px solid #eef3ff; padding-bottom:10px; margin-bottom:18px; }

    /* Vulnerability category box */
    .category-section {
      margin-bottom:24px;
      background: white;
      border-radius:8px;
      overflow: hidden;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }
    .category-section.risk-high { border-left: 6px solid #dc3545; }
    .category-section.risk-medium { border-left: 6px solid #fd7e14; }
    .category-section.risk-low { border-left: 6px solid #28a745; }

    .vuln-header { background: #f8f9fa; padding: 16px 20px; border-bottom: 2px solid #e9ecef; }
    .vuln-title { font-size: 18px; font-weight:700; color:#1a1a1a; margin-bottom:4px; }
    .vuln-content { padding: 20px; }

    .vuln-section { margin-bottom:20px; }
    .section-title { font-size: 14px; font-weight:700; color:#495057; margin-bottom:8px; text-transform:uppercase; letter-spacing:0.5px; }
    .section-content { font-size:14px; line-height:1.6; color:#2f3a47; }

    .risk-rating { display:flex; gap:20px; align-items:center; }
    .risk-item { display:flex; align-items:center; gap:8px; }
    .risk-label { font-weight:600; color:#495057; }
    .risk-value { padding:4px 12px; border-radius:4px; font-weight:700; font-size:13px; color:white; }
    .risk-value.high { background:#dc3545; }
    .risk-value.medium { background:#fd7e14; }
    .risk-value.low { background:#28a745; }

    .instances-table { width:100%; border-collapse:collapse; margin-top:8px; border:1px solid #dee2e6; font-size:13px; }
    .instances-table th { background:#f1f3f5; padding:10px 12px; text-align:left; font-weight:600; color:#495057; border-bottom:2px solid #dee2e6; }
    .instances-table td { padding:10px 12px; border-bottom:1px solid #e9ecef; color:#2f3a47; }
    .instances-table tr:last-child td { border-bottom:none; }
    .instances-table tr:hover { background:#f8f9fa; }
    .instances-table code { background:#e7f1ff; padding:2px 6px; border-radius:3px; font-family:monospace; font-size:12px; }

    .remediation-box { background:#fff3cd; border-left:4px solid #ffc107; padding:14px 16px; border-radius:4px; }
    .remediation-box .section-title { color:#856404; margin-bottom:8px; }
    .remediation-box .section-content { color:#664d03; }

    .report-footer { background:#f8fafc; padding:14px 32px; color:#5b6b7a; font-size:13px; border-top:1px solid #eef2fb; text-align:center; }

    /* responsive */
    @media (max-width:900px) {
      .page { width:calc(100% - 40px); }
      .summary { flex-direction:column; }
      .left-summary { width:100%; }
      .right-summary { width:100%; flex: none; margin-left:0; }
      .chart-container { width: 260px; height: 260px; }
    }

    /* print */
    @page { size: A4 portrait; margin: 12mm; }
    @media print {
      body { background: white; }
      .page { box-shadow:none; border-radius:0; width: auto; }
      .chart-wrapper, .card, .summary-table { page-break-inside: avoid; }
      .report-header, .meta, .report-footer { -webkit-print-color-adjust: exact; }
      .no-print { display:none !important; }
    }

    .anchor { display:block; padding-top:40px; margin-top:-40px; }
  </style>
</head>
<body>
  <div class="page" role="document">
    <!-- HEADER -->
    <header class="report-header">
      <div class="report-title">WebSecScan Security Report</div>
      <div class="report-sub">Web Application Security Analysis</div>
    </header>

    <!-- META -->
    <div class="meta">
      <div class="meta-item"><strong>Target:</strong> <code>{{ target_url }}</code></div>
      <div class="meta-item"><strong>Scan Time:</strong> {{ scan_time }}</div>
    </div>

    <!-- SUMMARY -->
    <section class="summary" aria-label="Executive summary">
      <div class="left-summary">
        <div class="stat-cards">
          <div class="card">
            <div class="num">{{ total_findings }}</div>
            <div class="label">Total Findings</div>
          </div>
          <div class="card">
            <div class="num" style="color:Red;">{{ total_high }}</div>
            <div class="label">High</div>
          </div>
          <div class="card">
            <div class="num" style="color:Orange;">{{ total_medium }}</div>
            <div class="label">Medium</div>
          </div>
          <div class="card">
            <div class="num" style="color:Green;">{{ total_low }}</div>
            <div class="label">Low</div>
          </div>
        </div>

        <table class="summary-table" role="table" aria-label="Findings summary by category">
          <thead>
            <tr><th>Category</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr>
          </thead>
          <tbody>
            {% for c in categories %}
            <tr>
              <td style="font-weight:700; color:#452829">{{ c.name }}</td>
              <td style="font-weight:700; color:Red">{{ c.high }}</td>
              <td style="font-weight:700; color:Orange">{{ c.medium }}</td>
              <td style="font-weight:700; color:Green">{{ c.low }}</td>
              <td style="font-weight:800; color:#452829">{{ (c.high|int + c.medium|int + c.low|int) }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

      <div class="right-summary">
        <div class="chart-wrapper" role="img" aria-label="Vulnerability categories chart">
          <div class="card-title">Vulnerability Categories Chart</div>
          <div class="chart-container">
            <canvas id="categoryChart"></canvas>
          </div>
          <div style="margin-top:16px;font-size:13px;font-weight:700;color:#5b6b7a;">
            Click a slice to jump to that details section.
          </div>
        </div>
      </div>
    </section>

    <!-- DETAILED FINDINGS -->
    <section class="details" id="details">
      <h2>🔍 Detailed Findings</h2>

      {% for c in categories %}
        {% set cat_name = c.name %}
        {% set findings = findings_by_category.get(cat_name, []) %}

        {# derive class based on summary counts #}
        {% set risk_class = 'risk-low' %}
        {% if c.high > 0 %}
          {% set risk_class = 'risk-high' %}
        {% elif c.medium > 0 %}
          {% set risk_class = 'risk-medium' %}
        {% endif %}

        <a id="anchor-{{ loop.index0 }}" class="anchor" aria-hidden="true"></a>
        <div class="category-section {{ risk_class }}" data-category="{{ cat_name|e }}">
          <div class="vuln-header">
            <div class="vuln-title">
              {{ vuln_defs.get(cat_name, {}).get('DisplayName') or cat_name }}
            </div>
          </div>

          <div class="vuln-content">
            {% if findings %}
              {% set first_finding = findings[0] %}

              <div class="vuln-section">
                <div class="section-title">Description</div>
                <div class="section-content">
                  {{ first_finding.get('Description', 'No description provided.') }}
                </div>
              </div>

              <div class="vuln-section">
                <div class="section-title">Risk Rating</div>
                <div class="risk-rating">
                  <div class="risk-item">
                    <span class="risk-label">Severity:</span>
                    {% if c.high > 0 %}
                      <span class="risk-value high">High</span>
                    {% elif c.medium > 0 %}
                      <span class="risk-value medium">Medium</span>
                    {% else %}
                      <span class="risk-value low">Low</span>
                    {% endif %}
                  </div>
                  <div class="risk-item">
                    <span class="risk-label">CVSS:</span>
                    <span class="risk-value {% if c.high > 0 %}high{% elif c.medium > 0 %}medium{% else %}low{% endif %}">
                      {{ first_finding.get('CVSS', 'N/A') }}
                    </span>
                  </div>
                </div>
              </div>

              <div class="vuln-section">
                <div class="section-title">Findings</div>
                <table class="instances-table" role="table" aria-label="Findings">
                  <thead>
                    <tr>
                      <th>Finding</th>
                      <th>Status</th>
                      <th>Current Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {% for f in findings %}
                      <tr>
                        <td style="font-weight:600;">{{ f.get('Context', f.get('Detail', 'Finding')) }}</td>
                        <td>{{ f.get('Status', 'Missing') }}</td>
                        <td><code>{{ f.get('Detail', '-') }}</code></td>
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>
              </div>

              {# IMPACT/CONSEQUENCE SECTION - Show all impacts #}
              <div class="vuln-section" style="margin-top:24px;">
                <div class="section-title" style="font-size:15px;text-transform:uppercase;letter-spacing:0.8px;color:#495057;">Impact / Consequence:</div>
                {% for f in findings %}
                  {% if f.get('Impact') %}
                    <div class="section-content" style="margin-top:12px;">
                      <div style="font-weight:600;color:#1a1a1a;margin-bottom:4px;">{{ f.get('Context', cat_name) }}</div>
                      <div style="padding-left:0px;">
                        {{ f.get('Impact', 'Impact information not available.') }}
                      </div>
                    </div>
                  {% endif %}
                {% endfor %}
              </div>

              {# REMEDIATION SECTION - Show all remediations #}
              <div class="vuln-section" style="margin-top:24px;">
                <div class="remediation-box">
                  <div class="section-title" style="font-size:15px;text-transform:uppercase;letter-spacing:0.8px;">Remediation:</div>
                  {% for f in findings %}
                    {% if f.get('Recommendation') %}
                      <div class="section-content" style="margin-top:12px;">
                        <div style="font-weight:600;color:#856404;margin-bottom:4px;">{{ f.get('Context', cat_name) }}</div>
                        <div style="padding-left:0px;">
                          {{ f.get('Recommendation') }}
                        </div>
                      </div>
                    {% endif %}
                  {% endfor %}
                </div>
              </div>

            {% else %}
              <div style="padding:10px;color:#5b6b7a;background:#f8f9fa;border-radius:6px;">
                No findings recorded for this category.
              </div>
            {% endif %}
          </div>
        </div>
      {% endfor %}
    </section>

    <footer class="report-footer">
      WebSecScan — Web Security Misconfiguration Analyzer · Generated {{ scan_time }} · <span style="opacity:.85">Lee Zhi Hui</span>
    </footer>
  </div>

  <!-- Chart.js script -->
  <script>
    (function(){
      const categories = [
        {% for c in categories %}
          { name: {{ c.name|tojson }}, high: {{ c.high|int }}, medium: {{ c.medium|int }}, low: {{ c.low|int }} }{% if not loop.last %},{% endif %}
        {% endfor %}
      ];
      const labels = categories.map(c => c.name);
      const values = categories.map(c => (c.high + c.medium + c.low));
      const palette = ['#FF6B6B','#FF9F43','#FFD43B','#6BCB77','#4D96FF','#845EC2','#00C9A7','#FF9671'];
      const colors = labels.map((_,i)=>palette[i%palette.length]);

      const ctx = document.getElementById('categoryChart').getContext('2d');
      const categoryChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data: values,
            backgroundColor: colors,
            borderWidth: 2,
            borderColor: '#fff',
            hoverOffset: 8,
            spacing: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          plugins: {
            legend: {
              position: 'right',
              labels: { 
                boxWidth: 14, 
                padding: 10, 
                usePointStyle: true,
                font: {
                  size: 12
                }
              }
            },
            tooltip: {
              callbacks: {
                label: (ctx) => `${ctx.label}: ${ctx.raw} findings`
              }
            }
          },
          onClick(evt) {
            const points = categoryChart.getElementsAtEventForMode(evt, 'nearest', { intersect: true }, true);
            if (!points.length) return;
            const idx = points[0].index;
            const anchorId = 'anchor-' + idx;
            const el = document.getElementById(anchorId);
            if (el) { 
              el.scrollIntoView({ behavior: 'smooth', block: 'start' }); 
              return; 
            }
            const catName = labels[idx];
            const sec = document.querySelector(`[data-category="${catName}"]`);
            if (sec) sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }
        }
      });

      // keyboard accessibility for chart wrapper
      const chartWrapper = document.querySelector('.chart-wrapper');
      if (chartWrapper) {
        chartWrapper.setAttribute('tabindex','0');
        chartWrapper.addEventListener('keydown', (e)=>{
          if (e.key === 'Enter' || e.key === ' ') {
            const details = document.getElementById('details');
            if (details) details.scrollIntoView({ behavior: 'smooth' });
            e.preventDefault();
          }
        });
      }
    })();
  </script>
</body>
</html>
"""

# ---------------------------
# Helper: transform your findings+summary into 'categories' and 'findings_by_category'
# ---------------------------
def _prepare_report_data(findings: List[Dict[str, Any]], summary: Dict[str, Dict[str, int]], debug: bool = False):
    """
    Build categories (list of {name, high, medium, low}) and findings_by_category (dict).
    This version ALWAYS computes counts from the actual `findings` list to avoid
    mismatches when `summary` is stale or empty. `summary` is used only as a
    preferred order if provided.

    Args:
        findings: list of finding dicts (each may have Category and Severity)
        summary: optional precomputed summary dict (category -> {High,Medium,Low})
        debug: if True, will print a short debug snapshot to stdout

    Returns:
        categories, findings_by_category
    """
    # 1) Group findings by category and count severities from actual findings
    findings_by_category: Dict[str, List[Dict[str, Any]]] = {}
    counts_by_category: Dict[str, Dict[str, int]] = {}

    for f in findings:
        # Normalize keys (support both "Category" and "category")
        cat = f.get("Category") or f.get("category") or "Uncategorized"
        sev = f.get("Severity") or f.get("severity") or "Low"
        sev = sev if sev in ("High", "Medium", "Low") else ("High" if sev.lower()=="high" else ("Medium" if sev.lower()=="medium" else "Low"))

        findings_by_category.setdefault(cat, []).append(f)
        if cat not in counts_by_category:
            counts_by_category[cat] = {"High": 0, "Medium": 0, "Low": 0}
        counts_by_category[cat][sev] = counts_by_category[cat].get(sev, 0) + 1

    # 2) If summary provided, try to use its order. Otherwise order by total counts desc.
    ordered_category_names = []
    if summary and isinstance(summary, dict) and len(summary) > 0:
        # preserve order of summary dict (likely insertion order from generate_summary)
        ordered_category_names = list(summary.keys())
        # But ensure we include any categories that appear in findings but not in summary
        for cat in counts_by_category.keys():
            if cat not in ordered_category_names:
                ordered_category_names.append(cat)
    else:
        # sort by total findings per category desc
        ordered_category_names = sorted(counts_by_category.keys(), key=lambda c: sum(counts_by_category[c].values()), reverse=True)

    # 3) Build final categories list using counts computed from findings
    categories = []
    for cat in ordered_category_names:
        cnts = counts_by_category.get(cat, {"High":0,"Medium":0,"Low":0})
        categories.append({"name": cat, "high": int(cnts.get("High", 0)), "medium": int(cnts.get("Medium", 0)), "low": int(cnts.get("Low", 0))})

    # 4) Add any categories present in findings but missing in ordered list (shouldn't happen, but safe)
    existing = set(ordered_category_names)
    for cat, cnts in counts_by_category.items():
        if cat not in existing:
            categories.append({"name": cat, "high": int(cnts.get("High", 0)), "medium": int(cnts.get("Medium", 0)), "low": int(cnts.get("Low", 0))})

    # Debugging snapshot
    if debug:
        try:
            print("DEBUG: derived categories (name, high, medium, low):")
            for c in categories:
                print(f"  - {c['name']}: H={c['high']} M={c['medium']} L={c['low']}")
            # show one example finding for each of first 3 categories (if present)
            shown = 0
            for cat in categories:
                if shown >= 3:
                    break
                items = findings_by_category.get(cat['name'], [])
                if items:
                    sample = items[0]
                    print(f"  SAMPLE for {cat['name']}: Severity={sample.get('Severity')} Desc={str(sample.get('Description',''))[:80]}")
                    shown += 1
        except Exception as e:
            print("[DEBUG] failed to print debug info:", e)

    return categories, findings_by_category


def generate_interactive_html_report(findings: List[Dict[str, Any]],
                                    summary: Dict[str, Dict[str, int]],
                                    filename: str = "security_scan_report.html",
                                    target_url: str = None) -> bool:
    """
    Generate an interactive HTML report using the embedded Jinja2 template.

    Notes:
      - The template uses Chart.js for interactive charts in the browser.
      - Findings are automatically enriched with detailed vulnerability information.
    """
    try:
        # ENRICH FINDINGS with detailed vulnerability information
        enriched_findings = enrich_all_findings(findings)
        
        # Ensure summary/findings are in expected shapes
        categories, findings_by_category = _prepare_report_data(enriched_findings, summary)

        # Totals
        total_high = sum(c["high"] for c in categories)
        total_medium = sum(c["medium"] for c in categories)
        total_low = sum(c["low"] for c in categories)
        total_findings = total_high + total_medium + total_low

        # Render the template using an Environment that enables `do`
        env = Environment(
            extensions=["jinja2.ext.do"],
            autoescape=select_autoescape(["html", "xml"]),
            undefined=StrictUndefined  # optional: helps catch missing keys early; remove if too strict
        )

        tmpl = env.from_string(REPORT_TEMPLATE)
        rendered = tmpl.render(
            target_url=target_url or "Unknown",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_findings=total_findings,
            total_high=total_high,
            total_medium=total_medium,
            total_low=total_low,
            categories=categories,
            findings_by_category=findings_by_category
            vuln_defs=VULNERABILITY_DEFINITIONS
        )

        # Write file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(rendered)

        print(Fore.GREEN + f"✅ Interactive HTML report generated: {filename}" + Style.RESET_ALL)
        print(Fore.CYAN + f"   Open the file in a browser to view and export the report." + Style.RESET_ALL)
        return True

    except Exception as e:
        print(Fore.RED + f"[ERROR] Failed to generate interactive HTML: {e}" + Style.RESET_ALL)
        import traceback
        traceback.print_exc()
        return False


# Legacy function for backward compatibility
def export_to_html(findings: List[Dict[str, Any]], summary: Dict[str, Dict[str, int]],
                   filename: str = "security_scan_report.html", target_url: str = None) -> bool:
    """Legacy function - redirects to interactive HTML generation."""
    return generate_interactive_html_report(findings, summary, filename, target_url)
'''


'''
# vulnerability_definitions.py
"""
Vulnerability Definitions Database

Contains detailed information (Description, Impact, CVSS) for each vulnerability category.
This data enriches findings before report generation.
"""

VULNERABILITY_DEFINITIONS = {
    "HTTP Security Headers": {
    
    "Description": """HTTP security headers provide yet another layer of security by helping to mitigate attacks and security vulnerabilities. Whenever a browser requests a page from a web server, the server responds with the content along with HTTP response headers. With the misconfigured or missing of HTTP security headers, the attackers may gain information from the data which may lead to various of attacks such as clickjacking, cross-site scripting (XSS) and others attacks as well.""",
    "CVSS": "3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)",

        # Per-header definitions used to build dynamic Impact/Recommendation
        "HeaderDetails": {
            "Strict-Transport-Security": {
                "Impact": "Missing Strict-Transport-Security allows downgrade attacks and enables interception of traffic as this header lets a website tell browsers that it should only be accessed using HTTPS, instead of using HTTP.",
                "Recommendation": "Enable HSTS with an appropriate max-age and includeSubDomains; consider preload where suitable."
            },
            "X-Frame-Options": {
                "Impact": "Missing X-Frame-Options allows clickjacking attacks.",
                "Recommendation": "Set X-Frame-Options to SAMEORIGIN or DENY to prevent framing by untrusted sites."
            },
            "X-Content-Type-Options": {
                "Impact": "Missing or insecure X-Content-Type-Options allows MIME-sniffing attacks, increasing XSS risk.",
                "Recommendation": "Set X-Content-Type-Options: nosniff on all responses."
            },
            "X-XSS-Protection": {
                "Impact": "Missing X-XSS-Protection increases exposure to reflected XSS attacks in older browsers.",
                "Recommendation": "Enable 'Content Security Policy' (CSP) that disables the use of inline JavaScript. Disable the 'X-XSS-Protection' by setting the following response header: 'X-XSS-Protection: 0'"
            },
            "Content-Security-Policy": {
                "Impact": "Missing Content-Security-Policy significantly increases exploitability of XSS vulnerabilities.",
                "Recommendation": "Set Content-Security-Policy: default-src 'self'; frame-ancestors 'none' to restrict script, frame, and resource loading sources."
            },
            "Cache-Control": {
                "Impact": "Missing or weak Cache-Control may expose sensitive information stored in browser cache.",
                "Recommendation": "Use Cache-Control: no-store,no-cache for sensitive pages to prevent caching."
            },
            "Referrer-Policy": {
                "Impact": "Missing Referrer-Policy may cause the browser to leak sensitive URL information to external sites during navigation.",
                "Recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin to limit referrer data sent to external origins."
            },
            "Cross-Origin-Opener-Policy": {
                "Impact": "Missing COOP allows external sites to open and interact with the browsing context, increasing risks such as cross-origin attacks and tab-nabbing.",
                "Recommendation": "Set Cross-Origin-Opener-Policy: same-origin to isolate the browsing context and enhance security."
            },
            "Cross-Origin-Embedder-Policy": {
                "Impact": "Missing COEP may allow the application to load untrusted cross-origin resources that are not opt-in, reducing the protection against cross-site data leaks.",
                "Recommendation": "Set Cross-Origin-Embedder-Policy: require-corp to ensure only secure, explicitly allowed resources can be embedded."
            },
            "Cross-Origin-Resource-Policy": {
                "Impact": "Missing CORP may allow other websites to load the resources cross-origin, potentially exposing sensitive data.",
                "Recommendation": "Set Cross-Origin-Resource-Policy: same-site to restrict resource usage to the same site."
            }
        }
    },
    
    "Unsafe HTTP Methods Enabled": {
        "Description": """HTTP offers a number of methods that can be used to perform actions on the web server. Many of these methods are designed to aid developers in deploying and testing HTTP applications. These HTTP methods can be used for nefarious purposes if the web server is misconfigured.

Some of these methods can potentially pose a security risk for a web application, as they allow a hacker to modify the files stored on the web server and, in some scenarios, steal the credentials of legitimate users. More specifically, the methods that should be disabled are the following:

- OPTIONS: This method is a diagnostic method which is mainly used for debugging purpose. It provides a list of the methods that are supported by the web server.
- TRACE: This method simply echoes back to the client whatever string has been sent to the server, and is used mainly for debugging purposes.
- PUT: This method allows a client to upload new files on the web server. An attacker can exploit it by uploading malicious files.
- DELETE: This method allows a client to delete a file on the web server. An attacker can exploit it as a very simple and direct way to deface a web site or to mount a Denial of Service (DoS) attack.
- DEBUG: This method is used for debugging purposes. It allows developers to diagnose and troubleshoot issues by providing detailed information about the server's operation.""",
        "CVSS": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        "Impact": """1. Sensitive server information can be retrieved and used by the attacker to plan further attacks and techniques.
2. Include content, scripts, binaries or images from potentially malicious sources.""",
        "Recommendation": "Disable methods such as OPTIONS, TRACE, PUT, DELETE or DEBUG."
    },
    
    "Security Headers": {
        "Description": """HTTP security headers are a fundamental part of website security. Upon implementation, they protect you against the types of attacks that your site is most likely to come across. These headers protect against XSS, code injection, clickjacking, and other common attacks.

Missing or misconfigured security headers can leave applications vulnerable to various client-side attacks including cross-site scripting (XSS), clickjacking, and information leakage.""",
        "CVSS": "3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)",
        "Impact": """1. Increased risk of cross-site scripting (XSS) attacks
2. Vulnerability to clickjacking attacks
3. Potential for MIME-type sniffing attacks
4. Exposure to man-in-the-middle attacks (if HSTS is missing)
5. Browser-based security features not properly utilized""",
        "Recommendation": """Implement the following security headers with appropriate values:
- Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
- Strict-Transport-Security: max-age=31536000; includeSubDomains
- X-Frame-Options: SAMEORIGIN / DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy: Configure based on required features"""
    },
    
    "Server Information": {
        "Description": """Web servers often expose detailed version information in HTTP response headers (Server, X-Powered-By) or error pages. This information disclosure can help attackers identify known vulnerabilities specific to the software versions in use.

Exposing server software versions, framework details, or technology stack information provides attackers with valuable reconnaissance data to craft targeted exploits.""",
        "CVSS": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        "Impact": """1. Attackers can identify specific software versions and search for known vulnerabilities
2. Technology stack information helps in crafting targeted attacks
3. Reduces the effort required for reconnaissance phase of attacks
4. May reveal end-of-life or outdated software in use""",
        "Recommendation": """1. Remove or obfuscate the Server header
2. Remove X-Powered-By and similar headers
3. Customize error pages to avoid exposing version information
4. Use reverse proxies or web application firewalls to mask backend technologies
5. Regularly update server software to latest secure versions"""
    },
    
    "Cookie Security": {
        "Description": """Cookies are small pieces of data stored by the browser that can contain sensitive information like session tokens, user preferences, and authentication data. Improperly configured cookies can be intercepted, manipulated, or stolen by attackers.

Cookie security attributes (Secure, HttpOnly, SameSite) are critical defenses against common web attacks including session hijacking, cross-site scripting (XSS), and cross-site request forgery (CSRF).""",
        "CVSS": "6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)",
        "Impact": """1. Session hijacking through cookie theft
2. Cross-site scripting (XSS) attacks can access sensitive cookies
3. Man-in-the-middle attacks can intercept cookies over insecure connections
4. Cross-site request forgery (CSRF) attacks
5. Unauthorized access to user accounts and sensitive data""",
        "Recommendation": """Set appropriate cookie attributes:
- Secure: Ensure cookies are only transmitted over HTTPS
- HttpOnly: Prevent JavaScript access to cookies
- SameSite: Set to 'Strict' or 'Lax' to prevent CSRF attacks
- Domain and Path: Scope cookies appropriately
- Expiration: Set reasonable expiration times for session cookies"""
    },
    
    "CORS Security": {
        "Description": """Cross-Origin Resource Sharing (CORS) is a mechanism that allows restricted resources on a web page to be requested from another domain. Misconfigured CORS policies can allow malicious websites to access sensitive data or perform actions on behalf of authenticated users.

An overly permissive CORS policy (especially using wildcards with credentials) can expose the application to data theft and unauthorized actions.""",
        "CVSS": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
        "Impact": """1. Unauthorized access to sensitive API endpoints from malicious origins
2. Data exfiltration to attacker-controlled domains
3. Theft of authentication tokens and session information
4. Ability to perform authenticated actions on behalf of victims
5. Bypass of same-origin policy protections""",
        "Recommendation": """1. Avoid using wildcard (*) in Access-Control-Allow-Origin with credentials
2. Explicitly whitelist trusted origins
3. Do not reflect Origin header without validation
4. Use Access-Control-Allow-Credentials: true only when necessary
5. Implement proper authentication and authorization checks server-side
6. Regularly audit CORS configurations"""
    },
    
    "Directory Exposure": {
        "Description": """Directory exposure occurs when web servers are misconfigured to display directory listings or when sensitive files and directories are accessible without proper authentication. This can reveal the application's file structure, backup files, configuration files, and other sensitive information.

Common exposed items include .git directories, backup files, configuration files, and development/testing resources that should not be publicly accessible.""",
        "CVSS": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)",
        "Impact": """1. Exposure of source code and sensitive configuration data
2. Discovery of backup files containing sensitive information
3. Revelation of application structure aiding further attacks
4. Access to credentials, API keys, or database connection strings
5. Discovery of hidden administrative interfaces
6. Information useful for social engineering attacks""",
        "Recommendation": """1. Disable directory listing in web server configuration
2. Remove or restrict access to .git, .svn, and other version control directories
3. Delete backup files, old code, and testing resources from production
4. Implement proper access controls for administrative areas
5. Use robots.txt carefully (does not provide security)
6. Regularly scan for exposed sensitive files
7. Implement proper file permissions on the server"""
    },
    
    "Path Traversal": {
        "Description": """Path traversal (also known as directory traversal) is a vulnerability that allows attackers to access files and directories stored outside the web root folder. By manipulating file path references using sequences like '../', attackers can break out of the intended directory structure.

This vulnerability typically occurs when user input is used to construct file paths without proper validation, allowing access to sensitive system files, application configuration, or other restricted resources.""",
        "CVSS": "7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
        "Impact": """1. Unauthorized access to sensitive files (passwords, configuration files, source code)
2. Exposure of system files (/etc/passwd, web server configs)
3. Access to application source code revealing business logic
4. Potential for privilege escalation
5. Information gathering for further attacks
6. In severe cases, ability to read private keys or credentials""",
        "Recommendation": """1. Validate and sanitize all user inputs used in file operations
2. Use whitelist approach for allowed files/paths
3. Implement proper access controls at the application level
4. Use built-in framework functions for file operations that handle path normalization
5. Run web server with minimal privileges
6. Disable dangerous functions in production (if using PHP: disable readfile, file_get_contents for user input)
7. Use chroot jails or containers to limit file system access
8. Regularly test for path traversal vulnerabilities"""
    },
    
    "SSL/TLS": {
        "Description": """SSL/TLS (Secure Sockets Layer/Transport Layer Security) provides encryption for data in transit between clients and servers. Weak SSL/TLS configurations, outdated protocols, weak ciphers, or certificate issues can expose communications to interception and manipulation.

Common issues include expired certificates, self-signed certificates in production, support for deprecated protocols (SSLv3, TLS 1.0, TLS 1.1), weak cipher suites, and missing security features like HSTS.""",
        "CVSS": "7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)",
        "Impact": """1. Man-in-the-middle attacks allowing traffic interception
2. Exposure of sensitive data transmitted over insecure connections
3. Session hijacking through unencrypted session tokens
4. Credential theft during authentication
5. Loss of user trust due to browser security warnings
6. Compliance violations (PCI-DSS, HIPAA, GDPR)
7. Vulnerability to known attacks (BEAST, POODLE, CRIME)""",
        "Recommendation": """1. Use valid certificates from trusted Certificate Authorities
2. Disable SSLv3, TLS 1.0, and TLS 1.1 - use TLS 1.2 or TLS 1.3
3. Configure strong cipher suites and disable weak ciphers
4. Implement HTTP Strict Transport Security (HSTS)
5. Enable Perfect Forward Secrecy (PFS)
6. Regularly monitor certificate expiration dates
7. Implement certificate pinning for mobile applications
8. Use tools like SSL Labs to test configuration
9. Keep OpenSSL/TLS libraries updated"""
    }
}


def enrich_finding_with_details(finding: dict) -> dict:
    """
    Enrich a finding dictionary with detailed information from the definitions database.
    
    Args:
        finding: A finding dict with at least 'Category' field
        
    Returns:
        Enriched finding dict with Description, CVSS, Impact, and Recommendation
    """
    category = finding.get("Category", "")
    
    # Try exact match first
    vuln_def = VULNERABILITY_DEFINITIONS.get(category)
    
    # If no exact match, try partial matching for common cases
    if not vuln_def:
        for def_category, details in VULNERABILITY_DEFINITIONS.items():
            if category.lower() in def_category.lower() or def_category.lower() in category.lower():
                vuln_def = details
                break
    
    # If still no match, provide generic information
    if not vuln_def:
        vuln_def = {
            "Description": finding.get("Description", "Security misconfiguration detected."),
            "CVSS": "N/A",
            "Impact": "This configuration may pose a security risk to the application.",
            "Recommendation": finding.get("Recommendation", "Review and remediate this security issue.")
        }
    
    # Create enriched finding
    enriched = finding.copy()
    
    # Add missing fields from definitions (don't override existing ones)
    if "Description" not in enriched or not enriched["Description"]:
        enriched["Description"] = vuln_def["Description"]
    
    if "CVSS" not in enriched or not enriched["CVSS"]:
        enriched["CVSS"] = vuln_def["CVSS"]
    
    if "Impact" not in enriched or not enriched["Impact"]:
        enriched["Impact"] = vuln_def["Impact"]
    
    if "Recommendation" not in enriched or not enriched["Recommendation"]:
        enriched["Recommendation"] = vuln_def["Recommendation"]
    
    return enriched


def enrich_all_findings(findings: list) -> list:
    """
    Enrich all findings in a list with detailed vulnerability information.
    
    Args:
        findings: List of finding dicts
        
    Returns:
        List of enriched finding dicts
    """
    return [enrich_finding_with_details(f) for f in findings]
'''