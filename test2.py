#export_findings.py
"""
Export Findings Module

Exports security scan findings to HTML, JSON, and PDF formats.
Generates interactive HTML reports with client-side export functionality.
"""

import json
from typing import List, Dict, Any
from datetime import datetime
from colorama import Fore, Style
import base64


def export_to_json(findings: List[Dict[str, Any]], summary: Dict[str, Dict[str, int]], 
                   filename: str = "security_scan_report.json", target_url: str = None) -> bool:
    """Export findings to a JSON file."""
    try:
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


def generate_interactive_html_report(findings: List[Dict[str, Any]], 
                                    summary: Dict[str, Dict[str, int]], 
                                    filename: str = "security_scan_report.html", 
                                    target_url: str = None) -> bool:
    """
    Generate an interactive HTML report with export functionality.
    The report includes a button to export to PDF/JSON and optionally email.
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
        
        # Generate report content HTML
        report_html = _generate_html_template(
            target_url=target_url or "Unknown",
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_findings=total_findings,
            total_high=total_high,
            total_medium=total_medium,
            total_low=total_low,
            sorted_categories=sorted_categories,
            findings_by_category=findings_by_category
        )
        
        # Embed findings data as JSON for client-side export
        findings_json = json.dumps({
            "scan_metadata": {
                "target_url": target_url or "Unknown",
                "scan_time": datetime.now().isoformat(),
                "total_findings": total_findings,
                "severity_counts": {
                    "High": total_high,
                    "Medium": total_medium,
                    "Low": total_low
                }
            },
            "summary": summary,
            "findings": findings
        }, indent=2)
        
        # Wrap in interactive HTML with export functionality
        html_content = _generate_interactive_wrapper(report_html, findings_json, target_url)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(Fore.GREEN + f"✅ Interactive HTML report generated: {filename}" + Style.RESET_ALL)
        print(Fore.CYAN + f"   Open the file in a browser to view and export the report." + Style.RESET_ALL)
        return True
        
    except Exception as e:
        print(Fore.RED + f"[ERROR] Failed to generate interactive HTML: {e}" + Style.RESET_ALL)
        return False


def _generate_interactive_wrapper(report_html: str, findings_json: str, target_url: str) -> str:
    """Wrap the report HTML with interactive export functionality (improved).

    Features:
    - Clean, accessible export modal (PDF / JSON / Email)
    - Sends full page HTML to backend only when PDF requested
    - Shows progress/spinner, disables UI during network activity
    - Validates email and selection, shows server response
    - Small safeguard: warns if HTML payload is large before attaching
    - Falls back to a local test file URL when `target_url` is empty
    """
    # fallback local file path (from uploaded file in the environment)
    fallback_local_file = "file:///mnt/data/cfeaa856-869c-4256-b71a-dbc3ca002ce3.png"

    # Ensure target_url is not None/empty in the rendered HTML (JS side will prefer passed value)
    safe_target = target_url if target_url else fallback_local_file

    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>WebSecScan Security Report — Interactive Export</title>
    <style>
        /* Reset for modal & button */
        .export-button {{
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 18px;
            border-radius: 10px;
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 6px 18px rgba(0,0,0,0.18);
            z-index: 1200;
        }}
        .export-button:disabled {{
            opacity: 0.6;
            cursor: not-allowed;
        }}

        /* Modal overlay */
        .modal {{
            display: none;
            position: fixed;
            z-index: 2000;
            inset: 0;
            background-color: rgba(0,0,0,0.55);
            padding: 40px 16px;
            overflow-y: auto;
        }}
        .modal-inner {{
            max-width: 680px;
            margin: 0 auto;
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 18px 60px rgba(0,0,0,0.25);
            padding: 22px;
        }}
        .modal-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            border-bottom: 3px solid #667eea;
            padding-bottom: 12px;
        }}
        .modal-title {{
            font-size: 20px;
            font-weight: 800;
            color: #243140;
        }}
        .close {{
            background: transparent;
            border: 0;
            font-size: 22px;
            cursor: pointer;
            color: #888;
        }}
        .close:hover {{ color: #333; }}

        .export-options {{
            margin-top: 18px;
            display: grid;
            gap: 10px;
        }}
        .export-option {{
            display: flex;
            gap: 12px;
            align-items: center;
            padding: 12px;
            border-radius: 8px;
            border: 1px solid #e9eef6;
            background: #fff;
        }}
        .export-option:hover {{
            border-color: #667eea;
            background: #fbfcff;
        }}
        .export-option input[type="checkbox"] {{ width:18px; height:18px; }}

        .email-section {{
            margin-top: 16px;
            padding: 12px;
            background: #f8f9fb;
            border-radius: 8px;
            border: 1px solid #eef2fb;
        }}
        .email-input {{
            display: block;
            width: 100%;
            padding: 10px;
            border-radius: 6px;
            border: 1px solid #dfe7f7;
            margin-top: 8px;
            font-size: 14px;
        }}

        .modal-actions {{
            display:flex;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 18px;
        }}
        .btn {{
            padding: 10px 16px;
            border-radius: 8px;
            border: 0;
            font-weight: 700;
            cursor: pointer;
        }}
        .btn-primary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .btn-muted {{
            background: #f1f4fb;
            color: #243140;
        }}

        .status {{

            margin-top: 14px;
        }}
        .success-message {{
            background: #e6f6ea;
            color: #0f5132;
            border: 1px solid #c7efd0;
            padding: 12px;
            border-radius: 8px;
            display: none;
        }}
        .error-message {{
            background: #fdecea;
            color: #83131b;
            border: 1px solid #f5c2c0;
            padding: 12px;
            border-radius: 8px;
            display: none;
        }}

        /* small spinner */
        .spinner {{
            display: inline-block;
            width: 18px;
            height: 18px;
            border-radius: 50%;
            border: 2px solid rgba(0,0,0,0.12);
            border-top-color: rgba(0,0,0,0.36);
            animation: spin 1s linear infinite;
            vertical-align: middle;
            margin-left: 10px;
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}

        /* ensure modal print-friendly */
        @media print {{
            .export-button, .modal {{ display: none !important; }}
        }}
    </style>
</head>
<body>
    <!-- Floating Export Button -->
    <button id="exportBtn" class="export-button" aria-haspopup="dialog" aria-controls="exportModal" title="Export report">📥 Export Report</button>

    <!-- Modal -->
    <div id="exportModal" class="modal" role="dialog" aria-modal="true" aria-labelledby="modalTitle">
        <div class="modal-inner" role="document">
            <div class="modal-header">
                <div>
                    <div id="modalTitle" class="modal-title">Export Security Report</div>
                    <div style="font-size:13px;color:#56606f;margin-top:4px;">Choose formats and optionally send the report by email</div>
                </div>
                <button class="close" aria-label="Close modal" id="closeModalBtn">&times;</button>
            </div>

            <div class="modal-body">
                <div class="export-options" role="group" aria-label="Export formats">
                    <label class="export-option">
                        <input type="checkbox" id="exportPDF" checked />
                        <div>
                            <div style="font-weight:700;">📄 PDF Report</div>
                            <div style="font-size:13px;color:#6c757d;">Download printable PDF version (browser print or server-generated when emailing)</div>
                        </div>
                    </label>

                    <label class="export-option">
                        <input type="checkbox" id="exportJSON" checked />
                        <div>
                            <div style="font-weight:700;">📊 JSON Data</div>
                            <div style="font-size:13px;color:#6c757d;">Download structured data for analysis</div>
                        </div>
                    </label>
                </div>

                <div class="email-section" aria-live="polite">
                    <label style="font-weight:700;">
                        <input type="checkbox" id="sendEmail" /> Send report to email (optional)
                    </label>
                    <input id="emailAddress" class="email-input" type="email" placeholder="recipient@example.com" disabled />
                    <div style="font-size:12px;color:#6b7280;margin-top:8px;">
                        If sending by email, a PDF will be generated server-side (if requested) and attachments sent.
                    </div>
                </div>

                <div id="statusArea" class="status" aria-live="polite" style="margin-top:12px;">
                    <div id="successMessage" class="success-message" role="status"></div>
                    <div id="errorMessage" class="error-message" role="alert"></div>
                </div>

                <div class="modal-actions">
                    <button id="cancelBtn" class="btn btn-muted">Cancel</button>
                    <button id="doExportBtn" class="btn btn-primary">Export</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Embedded report HTML (server-side injected) -->
    {report_html}

    <script>
    // ===== Embedded data and configuration =====
    const findingsData = {findings_json};
    const targetUrl = "{safe_target}";

    // Backend email API (explicit)
    const EMAIL_API = "http://localhost:5000/send-email";

    // UI elements
    const exportBtn = document.getElementById('exportBtn');
    const exportModal = document.getElementById('exportModal');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const cancelBtn = document.getElementById('cancelBtn');
    const doExportBtn = document.getElementById('doExportBtn');
    const exportPDFCheckbox = document.getElementById('exportPDF');
    const exportJSONCheckbox = document.getElementById('exportJSON');
    const sendEmailCheckbox = document.getElementById('sendEmail');
    const emailAddressInput = document.getElementById('emailAddress');
    const successMessage = document.getElementById('successMessage');
    const errorMessage = document.getElementById('errorMessage');
    const statusArea = document.getElementById('statusArea');

    // Open / close modal
    exportBtn.addEventListener('click', () => {{
        exportModal.style.display = 'block';
        // focus first control
        exportPDFCheckbox.focus();
    }});
    closeModalBtn.addEventListener('click', closeExportModal);
    cancelBtn.addEventListener('click', closeExportModal);
    function closeExportModal() {{
        exportModal.style.display = 'none';
        clearStatus();
    }}

    // Clicking outside modal closes it
    window.addEventListener('click', (ev) => {{
        if (ev.target === exportModal) {{
            closeExportModal();
        }}
    }});

    // Enable/disable email input
    sendEmailCheckbox.addEventListener('change', function() {{
        emailAddressInput.disabled = !this.checked;
        if (!this.checked) {{
            emailAddressInput.value = '';
        }}
    }});

    function clearStatus() {{
        successMessage.style.display = 'none';
        errorMessage.style.display = 'none';
        successMessage.textContent = '';
        errorMessage.textContent = '';
    }}

    // Simple email validation
    function isValidEmail(email) {{
        if (!email) return false;
        // basic regex for sanity check
        return /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email);
    }}

    // Prevent double-click spamming
    let inProgress = false;
    async function performExport() {{
        if (inProgress) return;
        clearStatus();

        const exportPDF = exportPDFCheckbox.checked;
        const exportJSON = exportJSONCheckbox.checked;
        const sendEmail = sendEmailCheckbox.checked;
        const emailAddress = (emailAddressInput.value || '').trim();

        if (!exportPDF && !exportJSON) {{
            errorMessage.textContent = 'Please select at least one export format.';
            errorMessage.style.display = 'block';
            return;
        }}
        if (sendEmail && !isValidEmail(emailAddress)) {{
            errorMessage.textContent = 'Please enter a valid recipient email address.';
            errorMessage.style.display = 'block';
            return;
        }}

        // UI lock
        inProgress = true;
        exportBtn.disabled = true;
        doExportBtn.disabled = true;
        cancelBtn.disabled = true;
        exportBtn.setAttribute('aria-disabled', 'true');

        // show spinner on Export button
        const spinner = document.createElement('span');
        spinner.className = 'spinner';
        doExportBtn.appendChild(spinner);

        try {{
            // 1) Trigger client-side JSON download immediately if requested
            if (exportJSON) {{
                downloadJSON();
            }}

            // 2) Trigger client-side PDF via print if only client PDF requested and NOT emailing
            let willSendToServer = sendEmail; // if emailing, server will generate PDF (more faithful)
            if (exportPDF && !willSendToServer) {{
                // hide export controls for clean print
                const currentExportBtnDisplay = exportBtn.style.display;
                const currentModalDisplay = exportModal.style.display;
                exportBtn.style.display = 'none';
                exportModal.style.display = 'none';
                // Print (user can Save as PDF)
                window.print();
                // restore
                exportBtn.style.display = currentExportBtnDisplay;
                exportModal.style.display = currentModalDisplay;
            }}

            // 3) If sending email, call backend
            if (sendEmail) {{
                // Build payload
                const payload = {{
                    recipient_email: emailAddress,
                    report_data: findingsData,
                    target_url: targetUrl,
                    include_pdf: !!exportPDF,
                    include_json: !!exportJSON
                }};

                // Attach full HTML only if PDF requested (avoid huge payloads otherwise)
                if (exportPDF) {{
                    try {{
                        // If document is huge, warn (over ~300KB)
                        const outer = document.documentElement.outerHTML;
                        if (outer.length > 300000) {{
                            // small, user-consent modal - here simplified as confirm()
                            if (!confirm('The report HTML is large and will be uploaded to the server to generate a faithful PDF (approx ' + Math.round(outer.length/1024) + ' KB). Continue?')) {{
                                throw new Error('User cancelled large HTML upload.');
                            }}
                        }}
                        payload.html = outer;
                    }} catch (e) {{
                        console.warn('Failed to capture outerHTML for PDF generation:', e);
                    }}
                }}

                // Perform fetch to backend
                const resp = await fetch(EMAIL_API, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify(payload)
                }});

                if (!resp.ok) {{
                    const txt = await resp.text();
                    throw new Error('Server responded with ' + resp.status + ': ' + txt);
                }}

                const json = await resp.json();
                if (json && json.success) {{
                    successMessage.textContent = json.message || 'Email queued/sent successfully.';
                    successMessage.style.display = 'block';
                }} else {{
                    const msg = (json && (json.error || json.details)) ? (json.error || json.details) : 'Unknown server error';
                    throw new Error(msg);
                }}
            }} else {{
                // No email requested; show local success message
                successMessage.textContent = 'Export completed locally.';
                successMessage.style.display = 'block';
            }}

        }} catch (err) {{
            errorMessage.textContent = 'Export failed: ' + (err && err.message ? err.message : String(err));
            errorMessage.style.display = 'block';
            console.error('Export error:', err);
        }} finally {{
            // restore UI
            inProgress = false;
            exportBtn.disabled = false;
            doExportBtn.disabled = false;
            cancelBtn.disabled = false;
            exportBtn.removeAttribute('aria-disabled');
            if (spinner && spinner.parentNode) spinner.parentNode.removeChild(spinner);
        }}
    }}

    // Attach event handlers
    doExportBtn.addEventListener('click', performExport);

    // Keyboard accessibility: close on Escape
    window.addEventListener('keydown', (e) => {{
        if (e.key === 'Escape') {{
            closeExportModal();
        }}
    }});

    // JSON download helper
    function downloadJSON() {{
        try {{
            const dataStr = JSON.stringify(findingsData, null, 2);
            const blob = new Blob([dataStr], {{ type: 'application/json' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security_scan_report_' + new Date().toISOString().split('T')[0] + '.json';
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        }} catch (e) {{
            console.error('Failed to download JSON:', e);
            throw e;
        }}
    }}

    </script>
</body>
</html>
"""

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
            
            .export-button {{
                display: none !important;
            }}
        }}
    </style>
    
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
"""
    
    return html


# Legacy function for backward compatibility
def export_to_html(findings: List[Dict[str, Any]], summary: Dict[str, Dict[str, int]], 
                   filename: str = "security_scan_report.html", target_url: str = None) -> bool:
    """Legacy function - redirects to interactive HTML generation."""
    return generate_interactive_html_report(findings, summary, filename, target_url)