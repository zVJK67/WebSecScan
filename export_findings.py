'''
"""
Export Findings Module

Exports security scan findings to HTML and JSON formats.

Usage:
    from export_findings import export_to_html, export_to_json
    
    export_to_html(all_findings, summary, "scan_report.html", target_url="https://example.com")
    export_to_json(all_findings, summary, "scan_report.json", target_url="https://example.com")
"""

import json
from typing import List, Dict, Any
from datetime import datetime
from colorama import Fore, Style


def export_to_json(findings: List[Dict[str, Any]], summary: Dict[str, Dict[str, int]], 
                   filename: str = "security_scan_report.json", target_url: str = None) -> bool:
    """
    Export findings to a JSON file.
    
    Args:
        findings: List of all findings
        summary: Summary dictionary from generate_summary()
        filename: Output filename
        target_url: Target URL that was scanned
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Calculate totals
        total_high = sum(counts["High"] for counts in summary.values())
        total_medium = sum(counts["Medium"] for counts in summary.values())
        total_low = sum(counts["Low"] for counts in summary.values())
        
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


def export_to_html(findings: List[Dict[str, Any]], summary: Dict[str, Dict[str, int]], 
                   filename: str = "security_scan_report.html", target_url: str = None) -> bool:
    """
    Export findings to an HTML file with styling.
    
    Args:
        findings: List of all findings
        summary: Summary dictionary from generate_summary()
        filename: Output filename
        target_url: Target URL that was scanned
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Sort categories by severity
        sorted_categories = sorted(
            summary.items(),
            key=lambda x: (x[1]["High"] * 100 + x[1]["Medium"] * 10 + x[1]["Low"]),
            reverse=True
        )
        
        # Calculate totals
        total_high = sum(counts["High"] for _, counts in sorted_categories)
        total_medium = sum(counts["Medium"] for _, counts in sorted_categories)
        total_low = sum(counts["Low"] for _, counts in sorted_categories)
        total_findings = total_high + total_medium + total_low
        
        # Group findings by category
        findings_by_category: Dict[str, List[Dict]] = {}
        for finding in findings:
            category = finding.get("Category", "Unknown")
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append(finding)
        
        # Sort findings within each category by severity
        severity_order = {"High": 0, "Medium": 1, "Low": 2}
        for category in findings_by_category:
            findings_by_category[category].sort(
                key=lambda f: severity_order.get(f.get("Severity", "Low"), 3)
            )
        
        # Generate HTML
        html_content = _generate_html_template(
            target_url=target_url or "Unknown",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_findings=total_findings,
            total_high=total_high,
            total_medium=total_medium,
            total_low=total_low,
            sorted_categories=sorted_categories,
            findings_by_category=findings_by_category
        )
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(Fore.GREEN + f"✅ HTML report exported to {filename}" + Style.RESET_ALL)
        return True
        
    except Exception as e:
        print(Fore.RED + f"[ERROR] Failed to export HTML: {e}" + Style.RESET_ALL)
        return False


def _generate_html_template(target_url: str, scan_time: str, total_findings: int,
                            total_high: int, total_medium: int, total_low: int,
                            sorted_categories: List, findings_by_category: Dict) -> str:
    """Generate the complete HTML document."""
    
    # Build summary table rows
    summary_rows = ""
    for category, counts in sorted_categories:
        high = counts["High"]
        medium = counts["Medium"]
        low = counts["Low"]
        total = high + medium + low
        
        severity_class = "severity-high" if high > 0 else ("severity-medium" if medium > 0 else "severity-low")
        
        summary_rows += f"""
        <tr class="{severity_class}">
            <td class="category-name">{category}</td>
            <td class="severity-high">{high}</td>
            <td class="severity-medium">{medium}</td>
            <td class="severity-low">{low}</td>
            <td class="total-col">{total}</td>
        </tr>
        """
    
    # Build detailed findings sections
    detailed_sections = ""
    for category, counts in sorted_categories:
        findings_list = findings_by_category.get(category, [])
        if not findings_list:
            continue
        
        high = counts["High"]
        medium = counts["Medium"]
        low = counts["Low"]
        
        findings_html = ""
        for idx, finding in enumerate(findings_list, 1):
            severity = finding.get("Severity", "Low")
            severity_class = f"severity-{severity.lower()}"
            description = finding.get("Description", "No description")
            recommendation = finding.get("Recommendation", "")
            
            # Additional details
            details_html = ""
            if finding.get("URL"):
                details_html += f'<div class="detail-item"><strong>URL:</strong> <code>{finding["URL"]}</code></div>'
            if finding.get("Context"):
                details_html += f'<div class="detail-item"><strong>Context:</strong> {finding["Context"]}</div>'
            if finding.get("Detail"):
                detail_val = finding["Detail"]
                if isinstance(detail_val, dict):
                    detail_val = json.dumps(detail_val, indent=2)
                details_html += f'<div class="detail-item"><strong>Detail:</strong> <pre>{detail_val}</pre></div>'
            if finding.get("Status"):
                details_html += f'<div class="detail-item"><strong>Status:</strong> {finding["Status"]}</div>'
            
            findings_html += f"""
            <div class="finding-item">
                <div class="finding-header">
                    <span class="finding-number">#{idx}</span>
                    <span class="severity-badge {severity_class}">{severity}</span>
                </div>
                <div class="finding-description">{description}</div>
                {details_html}
                {f'<div class="finding-recommendation"><strong>💡 Recommendation:</strong> {recommendation}</div>' if recommendation else ''}
            </div>
            """
        
        detailed_sections += f"""
        <section class="category-section">
            <h2 class="category-title">
                {category}
                <span class="category-badge">
                    <span class="severity-high">{high}</span> High | 
                    <span class="severity-medium">{medium}</span> Medium | 
                    <span class="severity-low">{low}</span> Low
                </span>
            </h2>
            <div class="findings-container">
                {findings_html}
            </div>
        </section>
        """
    
    # Complete HTML document
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSecScan Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        
        .header .subtitle {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .meta-info {{
            background: #f8f9fa;
            padding: 20px 40px;
            border-bottom: 2px solid #e9ecef;
        }}
        
        .meta-item {{
            display: inline-block;
            margin-right: 30px;
            margin-bottom: 10px;
        }}
        
        .meta-item strong {{
            color: #495057;
        }}
        
        .summary {{
            padding: 40px;
        }}
        
        .summary h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .stat-card .number {{
            font-size: 3em;
            font-weight: bold;
            display: block;
        }}
        
        .stat-card .label {{
            font-size: 1em;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .stat-card.high {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
        .stat-card.medium {{ background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }}
        .stat-card.low {{ background: linear-gradient(135deg, #30cfd0 0%, #330867 100%); }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
        }}
        
        th {{
            background: #2c3e50;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e9ecef;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .category-name {{
            font-weight: 600;
            color: #2c3e50;
        }}
        
        .severity-high {{
            color: #dc3545;
            font-weight: bold;
        }}
        
        .severity-medium {{
            color: #fd7e14;
            font-weight: bold;
        }}
        
        .severity-low {{
            color: #28a745;
            font-weight: bold;
        }}
        
        .total-col {{
            font-weight: bold;
            color: #495057;
        }}
        
        tfoot tr {{
            background: #f8f9fa;
            font-weight: bold;
            font-size: 1.1em;
        }}
        
        .details {{
            padding: 40px;
            background: #f8f9fa;
        }}
        
        .details h2 {{
            color: #2c3e50;
            margin-bottom: 30px;
            font-size: 1.8em;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .category-section {{
            background: white;
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .category-title {{
            color: #2c3e50;
            font-size: 1.5em;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }}
        
        .category-badge {{
            font-size: 0.7em;
            font-weight: normal;
        }}
        
        .findings-container {{
            display: grid;
            gap: 15px;
        }}
        
        .finding-item {{
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 20px;
            border-radius: 4px;
        }}
        
        .finding-item.severity-high {{
            border-left-color: #dc3545;
        }}
        
        .finding-item.severity-medium {{
            border-left-color: #fd7e14;
        }}
        
        .finding-item.severity-low {{
            border-left-color: #28a745;
        }}
        
        .finding-header {{
            display: flex;
            align-items: center;
            margin-bottom: 10px;
            gap: 10px;
        }}
        
        .finding-number {{
            background: #6c757d;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }}
        
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
        }}
        
        .severity-badge.severity-high {{
            background: #dc3545;
        }}
        
        .severity-badge.severity-medium {{
            background: #fd7e14;
        }}
        
        .severity-badge.severity-low {{
            background: #28a745;
        }}
        
        .finding-description {{
            color: #495057;
            margin-bottom: 15px;
            font-size: 1.05em;
        }}
        
        .detail-item {{
            background: white;
            padding: 10px;
            margin: 8px 0;
            border-radius: 4px;
            font-size: 0.95em;
        }}
        
        .detail-item strong {{
            color: #2c3e50;
        }}
        
        .detail-item code {{
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #e83e8c;
        }}
        
        .detail-item pre {{
            background: #2c3e50;
            color: #fff;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            margin-top: 5px;
            font-size: 0.9em;
        }}
        
        .finding-recommendation {{
            background: #e7f3ff;
            border-left: 3px solid #0066cc;
            padding: 12px;
            margin-top: 12px;
            border-radius: 4px;
            color: #004080;
        }}
        
        .footer {{
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ WebSecScan Security Report</h1>
            <div class="subtitle">Comprehensive Security Analysis</div>
        </div>
        
        <div class="meta-info">
            <div class="meta-item">
                <strong>Target URL:</strong> <code>{target_url}</code>
            </div>
            <div class="meta-item">
                <strong>Scan Date:</strong> {scan_time}
            </div>
            <div class="meta-item">
                <strong>Total Findings:</strong> {total_findings}
            </div>
        </div>
        
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <span class="number">{total_findings}</span>
                    <span class="label">Total Issues</span>
                </div>
                <div class="stat-card high">
                    <span class="number">{total_high}</span>
                    <span class="label">High Severity</span>
                </div>
                <div class="stat-card medium">
                    <span class="number">{total_medium}</span>
                    <span class="label">Medium Severity</span>
                </div>
                <div class="stat-card low">
                    <span class="number">{total_low}</span>
                    <span class="label">Low Severity</span>
                </div>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>High</th>
                        <th>Medium</th>
                        <th>Low</th>
                        <th>Total</th>
                    </tr>
                </thead>
                <tbody>
                    {summary_rows}
                </tbody>
                <tfoot>
                    <tr>
                        <td>TOTAL</td>
                        <td class="severity-high">{total_high}</td>
                        <td class="severity-medium">{total_medium}</td>
                        <td class="severity-low">{total_low}</td>
                        <td class="total-col">{total_findings}</td>
                    </tr>
                </tfoot>
            </table>
        </div>
        
        <div class="details">
            <h2>🔍 Detailed Findings</h2>
            {detailed_sections}
        </div>
        
        <div class="footer">
            <p>WebSecScan — Web Security Misconfiguration Analyzer</p>
            <p>Developed by Lee Zhi Hui</p>
        </div>
    </div>
</body>
</html>
"""
    
    return html


# Example usage
if __name__ == "__main__":
    from findings_summary import generate_summary
    
    # Sample data
    sample_findings = [
        {
            "Category": "Security Headers",
            "Severity": "High",
            "Description": "Content-Security-Policy header is missing",
            "Recommendation": "Add a CSP header to control sources of scripts, styles, and media."
        },
        {
            "Category": "CORS",
            "Severity": "High",
            "Description": "Wildcard origin with credentials enabled",
            "Recommendation": "Do not use '*' with credentials. Return explicit trusted origin(s) instead.",
            "Context": "Observed in probe response"
        },
    ]
    
    summary = generate_summary(sample_findings)
    
    # Export examples
    export_to_html(sample_findings, summary, "test_report.html", "https://example.com")
    export_to_json(sample_findings, summary, "test_report.json", "https://example.com")
    '''

"""
Export Findings Module

Exports security scan findings to HTML and JSON formats.

Usage:
    from export_findings import export_to_html, export_to_json
    
    export_to_html(all_findings, summary, "scan_report.html", target_url="https://example.com")
    export_to_json(all_findings, summary, "scan_report.json", target_url="https://example.com")
"""

import json
from typing import List, Dict, Any
from datetime import datetime
from colorama import Fore, Style


def export_to_json(findings: List[Dict[str, Any]], summary: Dict[str, Dict[str, int]], 
                   filename: str = "security_scan_report.json", target_url: str = None) -> bool:
    """
    Export findings to a JSON file.
    
    Args:
        findings: List of all findings
        summary: Summary dictionary from generate_summary()
        filename: Output filename
        target_url: Target URL that was scanned
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Calculate totals
        total_high = sum(counts["High"] for counts in summary.values())
        total_medium = sum(counts["Medium"] for counts in summary.values())
        total_low = sum(counts["Low"] for counts in summary.values())
        
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


def export_to_pdf(findings: List[Dict[str, Any]],
                  summary: Dict[str, Dict[str, int]],
                  filename: str = "security_scan_report.pdf",
                  target_url: str = None) -> bool:
    """
    Export findings to a PDF file by rendering an HTML template and converting it with WeasyPrint.
    Requires: weasyprint (and system libs: cairo, pango).
    """
    try:
        # lazy import so script won't fail when not using PDF
        from weasyprint import HTML, CSS
    except Exception as e:
        print(Fore.RED + "[ERROR] WeasyPrint is required to export PDF. Install it and system dependencies." + Style.RESET_ALL)
        print(Fore.RED + f"Details: {e}" + Style.RESET_ALL)
        return False

    try:
        # Sort categories by severity (same logic you used before)
        sorted_categories = sorted(
            summary.items(),
            key=lambda x: (x[1]["High"] * 100 + x[1]["Medium"] * 10 + x[1]["Low"]),
            reverse=True
        )

        # Calculate totals
        total_high = sum(counts["High"] for _, counts in sorted_categories)
        total_medium = sum(counts["Medium"] for _, counts in sorted_categories)
        total_low = sum(counts["Low"] for _, counts in sorted_categories)
        total_findings = total_high + total_medium + total_low

        # Group findings by category and sort by severity
        findings_by_category: Dict[str, List[Dict]] = {}
        for finding in findings:
            category = finding.get("Category", "Unknown")
            findings_by_category.setdefault(category, []).append(finding)

        severity_order = {"High": 0, "Medium": 1, "Low": 2}
        for category in findings_by_category:
            findings_by_category[category].sort(key=lambda f: severity_order.get(f.get("Severity", "Low"), 3))

        # Build HTML (same function used for PDF rendering)
        html_content = _generate_html_template(
            target_url=target_url or "Unknown",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_findings=total_findings,
            total_high=total_high,
            total_medium=total_medium,
            total_low=total_low,
            sorted_categories=sorted_categories,
            findings_by_category=findings_by_category
        )

        # Render PDF
        HTML(string=html_content).write_pdf(filename)
        print(Fore.GREEN + f"✅ PDF report exported to {filename}" + Style.RESET_ALL)
        return True

    except Exception as e:
        print(Fore.RED + f"[ERROR] Failed to export PDF: {e}" + Style.RESET_ALL)
        return False


# --- UPDATED: HTML template generator (produces HTML that WeasyPrint can render to PDF) ---
def _generate_html_template(target_url: str, scan_time: str, total_findings: int,
                            total_high: int, total_medium: int, total_low: int,
                            sorted_categories: List, findings_by_category: Dict) -> str:
    """
    Generate an HTML document string which is suitable for WeasyPrint rendering to PDF.
    Includes an inline SVG donut chart (no JS required).
    """
    # Build summary table rows
    summary_rows = ""
    for category, counts in sorted_categories:
        high = counts["High"]
        medium = counts["Medium"]
        low = counts["Low"]
        total = high + medium + low
        summary_rows += f"""
        <tr>
            <td style="padding:8px 10px;border-bottom:1px solid #ddd;">{category}</td>
            <td style="padding:8px 10px;border-bottom:1px solid #ddd;">{high}</td>
            <td style="padding:8px 10px;border-bottom:1px solid #ddd;">{medium}</td>
            <td style="padding:8px 10px;border-bottom:1px solid #ddd;">{low}</td>
            <td style="padding:8px 10px;border-bottom:1px solid #ddd;"><strong>{total}</strong></td>
        </tr>
        """

    # Build detailed findings
    detailed_sections = ""
    finding_global_index = 1
    for category, counts in sorted_categories:
        findings_list = findings_by_category.get(category, [])
        if not findings_list:
            continue

        # Section header with counts
        detailed_sections += f"""
        <div class="category-section">
            <h2 style="margin:0 0 8px 0;font-size:18px;color:#222;">{category}
                <span style="float:right;font-size:13px;color:#555;">
                    {counts['High']} High | {counts['Medium']} Medium | {counts['Low']} Low
                </span>
            </h2>
        """

        for f in findings_list:
            severity = f.get("Severity", "Low")
            severity_color = "#dc3545" if severity == "High" else ("#fd7e14" if severity == "Medium" else "#28a745")
            description = f.get("Description", "No description provided.")
            recommendation = f.get("Recommendation", "No recommendation provided.")
            url = f.get("URL", "N/A")
            context = f.get("Context", "N/A")
            detail_val = f.get("Detail", "")
            if isinstance(detail_val, dict):
                detail_val = json.dumps(detail_val, indent=2)

            detail_block = ""
            if detail_val:
                detail_block = f'<div style="background:#f7f7f7;padding:8px;border-radius:4px;margin:6px 0;"><pre style="white-space:pre-wrap;margin:0;">{detail_val}</pre></div>'

            detailed_sections += f"""
            <div style="margin:14px 0;padding:12px;border-left:6px solid {severity_color};background:#fff;border-radius:4px;">
                <div style="font-weight:700;margin-bottom:6px;">#{finding_global_index} — {description}</div>
                <div style="margin-bottom:6px;"><strong>Risk rating:</strong> <span style="color:{severity_color};font-weight:700;">{severity}</span></div>

                <div style="margin-bottom:6px;"><strong>Instances:</strong><br><code style="background:#f1f1f1;padding:2px 6px;border-radius:3px;">{url}</code></div>
                <div style="margin-bottom:6px;"><strong>Page Affected / Context:</strong><br>{context}</div>

                <div style="margin-bottom:6px;"><strong>Impact/Consequence:</strong><br>
                    Exploitation of this issue may allow unauthorized access, data leakage, or system compromise depending on the nature of the vulnerability.
                </div>

                <div style="margin-bottom:6px;background:#fffbe6;padding:8px;border-left:4px solid #ffd43b;border-radius:3px;"><strong>Remediation:</strong><br>{recommendation}</div>

                {detail_block}
            </div>
            """
            finding_global_index += 1

        detailed_sections += "</div>"

    # Build small inline SVG donut (proportions)
    total_for_chart = float(total_high + total_medium + total_low) or 1.0
    ph = (total_high / total_for_chart) * 100
    pm = (total_medium / total_for_chart) * 100
    pl = (total_low / total_for_chart) * 100

    # use stroke-dasharray on circles to make donut segments
    # We'll create concentric arcs by rotating stroke-dasharray. This is a simple representation.
    svg_donut = f"""
    <svg width="220" height="220" viewBox="0 0 42 42" class="donut">
      <defs></defs>
      <circle r="15.9155" cx="21" cy="21" fill="transparent" stroke="#eee" stroke-width="8"></circle>

      <!-- High -->
      <circle r="15.9155" cx="21" cy="21" fill="transparent" stroke="#dc3545" stroke-width="8"
              stroke-dasharray="{ph} {100-ph}" stroke-dashoffset="0" transform="rotate(-90 21 21)"></circle>

      <!-- Medium -->
      <circle r="15.9155" cx="21" cy="21" fill="transparent" stroke="#fd7e14" stroke-width="8"
              stroke-dasharray="{pm} {100-pm}" stroke-dashoffset="{ -ph }" transform="rotate(-90 21 21)"></circle>

      <!-- Low -->
      <circle r="15.9155" cx="21" cy="21" fill="transparent" stroke="#28a745" stroke-width="8"
              stroke-dasharray="{pl} {100-pl}" stroke-dashoffset="{ -(ph+pm) }" transform="rotate(-90 21 21)"></circle>

      <g font-family="Arial" font-size="3" text-anchor="middle">
        <text x="21" y="20.5" style="font-size:3.6px;font-weight:700;">{int(total_for_chart)}</text>
        <text x="21" y="24.5" style="fill:#666;">Total</text>
      </g>
    </svg>
    """

    # Compose full HTML
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>WebSecScan Security Report</title>
<style>
  body {{
    font-family: 'Helvetica Neue', Arial, sans-serif;
    color:#222;
    margin: 24px;
    background: #fff;
  }}
  .header {{
    background:#4a60e0;
    color:#fff;
    padding:18px 20px;
    border-radius:6px;
  }}
  .meta {{
    margin-top:14px;
    display:flex;
    gap:40px;
    align-items:center;
  }}
  .meta .left {{
    flex:1;
  }}
  .meta .right {{
    width:220px;
    text-align:center;
  }}
  table.summary {{
    width:100%;
    border-collapse:collapse;
    margin-top:12px;
  }}
  table.summary th {{
    background:#2c3e50;
    color:#fff;
    text-align:left;
    padding:10px;
  }}
  table.summary td {{
    padding:8px 10px;
    border-bottom:1px solid #eee;
  }}
  .category-section {{
    margin-top:18px;
  }}
  .donut {{
    margin-top:6px;
  }}
  pre {{
    font-family: monospace;
  }}
</style>
</head>
<body>
  <div class="header">
    <h1 style="margin:0;font-size:20px;">WebSecScan Security Report</h1>
    <div style="opacity:0.9;margin-top:6px;">Comprehensive Security Analysis</div>
  </div>

  <div class="meta" style="margin-top:12px;">
    <div class="left">
      <div><strong>Target URL:</strong> <code>{target_url}</code></div>
      <div style="margin-top:6px;"><strong>Scan Date:</strong> {scan_time}</div>
      <div style="margin-top:6px;"><strong>Total Findings:</strong> {total_findings}</div>
    </div>

    <div class="right">
      <div style="display:inline-block;padding:8px;background:#d62828;color:#fff;border-radius:4px;font-weight:700;">RISK: CRITICAL</div>
      {svg_donut}
      <div style="font-size:12px;margin-top:6px;">
        <span style="color:#dc3545;">High: {total_high}</span> &nbsp;|&nbsp;
        <span style="color:#fd7e14;">Medium: {total_medium}</span> &nbsp;|&nbsp;
        <span style="color:#28a745;">Low: {total_low}</span>
      </div>
    </div>
  </div>

  <h2 style="margin-top:18px;">Identified Vulnerabilities — Categories</h2>

  <table class="summary" aria-label="Summary table">
    <thead>
      <tr>
        <th>Category</th>
        <th>High</th>
        <th>Medium</th>
        <th>Low</th>
        <th>Total</th>
      </tr>
    </thead>
    <tbody>
      {summary_rows}
    </tbody>
  </table>

  <h2 style="margin-top:18px;">Detailed Findings</h2>
  {detailed_sections}

</body>
</html>
"""
    return html


# Example usage
if __name__ == "__main__":
    from findings_summary import generate_summary
    
    # Sample data
    sample_findings = [
        {
            "Category": "Security Headers",
            "Severity": "High",
            "Description": "Content-Security-Policy header is missing",
            "Recommendation": "Add a CSP header to control sources of scripts, styles, and media."
        },
        {
            "Category": "CORS",
            "Severity": "High",
            "Description": "Wildcard origin with credentials enabled",
            "Recommendation": "Do not use '*' with credentials. Return explicit trusted origin(s) instead.",
            "Context": "Observed in probe response"
        },
    ]
    
    summary = generate_summary(sample_findings)
    
    # Export examples
    export_to_html(sample_findings, summary, "test_report.html", "https://example.com")
    export_to_json(sample_findings, summary, "test_report.json", "https://example.com")