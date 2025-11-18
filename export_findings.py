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
    
    # Build summary rows
    summary_rows = ""
    for category, counts in sorted_categories:
        total = counts["High"] + counts["Medium"] + counts["Low"]
        summary_rows += f"""
            <tr>
                <td>{category}</td>
                <td>{counts['High']}</td>
                <td>{counts['Medium']}</td>
                <td>{counts['Low']}</td>
                <td><strong>{total}</strong></td>
            </tr>
        """

    # Build detailed finding blocks
    detailed_html = ""
    for category, counts in sorted_categories:
        findings = findings_by_category.get(category, [])
        if not findings:
            continue
        
        for finding in findings:
            detailed_html += f"""
            <div class="finding-block">
                <h3 class="finding-title">Vulnerability: {finding.get("Description", "Unnamed Finding")}</h3>

                <p><strong>Risk rating:</strong> <span class="severity">{finding.get("Severity")}</span></p>

                <p><strong>Instances:</strong><br> {finding.get("URL", "N/A")}</p>
                <p><strong>Page Affected:</strong><br> {finding.get("Context", "N/A")}</p>

                <p><strong>Impact/Consequence:</strong><br>
                    Attackers may exploit this vulnerability to gain unauthorized access or compromise the system.
                </p>

                <p><strong>Remediation:</strong><br>
                    {finding.get('Recommendation', "No remediation provided.")}
                </p>
            </div>
            <hr>
            """

    # The chart data
    categories = [c for c, _ in sorted_categories]
    highs = [counts["High"] for _, counts in sorted_categories]
    meds = [counts["Medium"] for _, counts in sorted_categories]
    lows = [counts["Low"] for _, counts in sorted_categories]

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>WebSecScan Security Report</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #fff;
}}

.header {{
    background: #4A60E0;
    padding: 25px;
    color: white;
}}

.header h1 {{
    font-size: 32px;
}}

.info-box {{
    margin-top: 20px;
}}

.summary-table table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}}

.summary-table th {{
    background: #2c3e50;
    color: white;
    padding: 10px;
    text-align: left;
}}

.summary-table td {{
    padding: 8px;
    border-bottom: 1px solid #ccc;
}}

.finding-block {{
    margin-top: 30px;
}}

.finding-title {{
    font-size: 20px;
    color: #2c3e50;
}}

.severity {{
    color: red;
    font-weight: bold;
}}

.red-box {{
    width: 150px;
    background: #d62828;
    padding: 10px;
    color: white;
    font-weight: bold;
    text-align: center;
    border-radius: 6px;
}}
</style>
</head>

<body>

<div class="header">
    <h1>WebSecScan Security Report</h1>
    <div>Comprehensive Security Analysis</div>
</div>

<div class="info-box">
    <p><strong>Target URL:</strong> {target_url}</p>
    <p><strong>Scan Time:</strong> {scan_time}</p>
    <p><strong>Total Findings:</strong> {total_findings}</p>
    <div class="red-box">Risk Level: CRITICAL</div>
</div>

<h2>Identified Vulnerabilities</h2>

<canvas id="donutChart" width="260" height="260"></canvas>

<script>
const ctx = document.getElementById('donutChart').getContext('2d');
new Chart(ctx, {{
    type: 'doughnut',
    data: {{
        labels: {categories},
        datasets: [{{
            data: { [sum(x) for x in zip(highs, meds, lows)] },
            backgroundColor: ['#ff4d4d','#ffa502','#2ed573','#1e90ff','#5352ed','#3742fa']
        }}]
    }},
    options: {{
        cutout: '50%',
        responsive: false
    }}
}});
</script>

<h2>Categories</h2>

<div class="summary-table">
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
</table>
</div>

<h2>Detailed Findings</h2>

{detailed_html}

<br><br>

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