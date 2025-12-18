"""
Email Server with PDF-safe SVG Chart Rendering
(Flex-free, WeasyPrint compatible)
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from optional_email import send_report_email
import json
import os
import math
import re
from datetime import datetime
import tempfile
import traceback
from export_findings import export_to_json
from flask import send_file

app = Flask(__name__)
CORS(app)

# Email configuration
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
SENDER_PASSWORD = os.environ.get("SENDER_PASSWORD")
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))

try:
    from weasyprint import HTML, CSS
    from weasyprint.text.fonts import FontConfiguration
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False


# =========================================================
# SVG PIE CHART (PDF SAFE)
# =========================================================
def generate_svg_pie_chart(categories, width=400, height=400):
    data = []
    for cat in categories:
        total = cat.get("high", 0) + cat.get("medium", 0) + cat.get("low", 0)
        if total > 0:
            data.append({
                "name": cat.get("display_name", cat.get("name", "Unknown")),
                "value": total
            })

    if not data:
        return (
            f'<svg viewBox="0 0 {width} {height}" '
            f'width="{width}" height="{height}">'
            '<text x="50%" y="50%" text-anchor="middle" fill="#999">'
            'No data</text></svg>'
        )

    colors = [
        "#FF6B6B", "#FF9F43", "#FFD43B", "#6BCB77",
        "#4D96FF", "#845EC2", "#00C9A7", "#FF9671"
    ]

    total = sum(item["value"] for item in data)
    cx, cy = width / 2, height / 2
    radius = min(width, height) / 2 - 40

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" '
        f'preserveAspectRatio="xMidYMid meet">'
    ]

    angle = -90
    for i, item in enumerate(data):
        sweep = item["value"] / total * 360
        end = angle + sweep

        x1 = cx + radius * math.cos(math.radians(angle))
        y1 = cy + radius * math.sin(math.radians(angle))
        x2 = cx + radius * math.cos(math.radians(end))
        y2 = cy + radius * math.sin(math.radians(end))

        large = 1 if sweep > 180 else 0
        color = colors[i % len(colors)]

        svg.append(
            f'<path d="M{cx},{cy} L{x1},{y1} '
            f'A{radius},{radius} 0 {large},1 {x2},{y2} Z" '
            f'fill="{color}" stroke="#fff" stroke-width="2"/>'
        )
        angle = end

    svg.append("</svg>")
    return "".join(svg)


# =========================================================
# HTML → PDF CONVERSION
# =========================================================
def convert_html_for_pdf(html: str, report_data: dict) -> str:
    """
    Enable SVG chart rendering using existing Jinja template logic.
    """
    categories = report_data.get("summary", [])

    svg_chart = generate_svg_pie_chart(categories)

    # Inject flags BEFORE </head>
    inject = f"""
    <script>
      window.__USE_SVG_CHART__ = true;
    </script>
    """

    html = html.replace("</head>", inject + "</head>")

    # Replace Jinja placeholders safely
    html = html.replace(
        "{% if use_svg_chart %}",
        ""
    ).replace(
        "{% else %}",
        ""
    ).replace(
        "{% endif %}",
        ""
    )

    html = html.replace(
        "{{ svg_chart|safe }}",
        svg_chart
    )

    # Remove Chart.js
    html = re.sub(
        r'<script src="https://cdn\.jsdelivr\.net/npm/chart\.js.*?</script>',
        "",
        html,
        flags=re.DOTALL
    )

    html = re.sub(
        r'<script>\s*\(function\(\)\{.*?new Chart.*?\}\)\(\);\s*</script>',
        "",
        html,
        flags=re.DOTALL
    )

    return html

# =========================================================
# PDF GENERATION
# =========================================================
def generate_pdf_from_html(html, output_path, report_data):
    if not WEASYPRINT_AVAILABLE:
        return False, "WeasyPrint not installed"

    try:
        html = convert_html_for_pdf(html, report_data)

        font_config = FontConfiguration()

        pdf_css = CSS(string="""
            @page { 
                size: A4 portrait; 
                margin: 12mm;
            }

            body {
                background: white;
            }

            .no-print,
            .export-modal,
            .export-main-btn,
            #openExportBtn {
                display: none !important;
            }
                      
            /* 🚨 1. REMOVE HEIGHT LOCK (THIS WAS THE REAL KILLER) */
            html, body {
                height: auto !important;
            }

            /* 🚨 2. ALLOW PAGE CONTENT TO FLOW */
            .page {
                overflow: visible !important;
            }

            /* 🚨 3. FORCE DETAILS TO PAGE 2 */
            .details {
                page-break-before: always;
            }

            /* ===== CRITICAL: REMOVE FLEXBOX FOR PDF ===== */
            .summary {
                display: block !important;
                page-break-inside: avoid;
            }

            .left-summary,
            .right-summary {
                width: 100% !important;
                margin: 0 !important;
                display: block !important;
            }

            /* ===== FIX: CHART SIZING ===== */
            .chart-wrapper {
                min-height: auto !important;
                height: auto !important;
                padding: 16px !important;
                margin: 16px 0 !important;
                page-break-inside: avoid;
                display: block !important;
            }

            .chart-container {
                width: 100% !important;
                height: auto !important;
                display: block !important;
            }

            .svg-chart-wrapper svg,
            .chart-container svg {
                width: 300px !important;
                height: 300px !important;
                display: block !important;
                margin: 0 auto !important;
            }

            /* ===== FIX: REMOVE BLANK SPACE IN CATEGORIES ===== */
            .category-section {
                page-break-inside: auto !important;
                margin-bottom: 16px !important;
            }

            .vuln-content {
                padding: 16px !important;
            }

            .vuln-section {
                page-break-inside: avoid;
            }

            /* ===== FIX: TABLE SPACING ===== */
            .instances-table {
                margin-top: 8px !important;
                page-break-inside: auto;
            }

            .instances-table tbody tr {
                page-break-inside: avoid;
            }

            /* ===== FIX: REMEDIATION BOX ===== */
            .remediation-box {
                margin-top: 12px !important;
                page-break-inside: avoid;
            }

            /* ===== PRESERVE COLORS ===== */
            .report-header, 
            .meta, 
            .report-footer,
            .chart-wrapper,
            .card,
            .stat-cards .card,
            .risk-value.high,
            .risk-value.medium,
            .risk-value.low,
            .category-section.risk-high,
            .category-section.risk-medium,
            .category-section.risk-low,
            .remediation-box {
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
                color-adjust: exact !important;
            }

            /* ===== SUMMARY TABLE COMPACT ===== */
            .summary-table {
                margin-top: 10px !important;
                margin-bottom: 16px !important;
            }

            .stat-cards {
                margin-bottom: 12px !important;
            }

            /* ===== REMOVE EXCESSIVE MARGINS ===== */
            .details {
                padding: 16px 32px 24px !important;
            }

            h2 {
                margin-top: 8px !important;
                margin-bottom: 12px !important;
            }
            """, font_config=font_config)

        HTML(string=html).write_pdf(
            output_path,
            stylesheets=[pdf_css],
            font_config=font_config
        )

        return True, None

    except Exception as e:
        traceback.print_exc()
        return False, str(e)


# =========================================================
# EMAIL ENDPOINT
# =========================================================
@app.route("/send-email", methods=["POST"])
def send_email():
    try:
        data = request.get_json()

        recipient_email = data.get("recipient_email")
        html = data.get("html")
        target_url = data.get("target_url", "Unknown")

        include_pdf = data.get("include_pdf", False)
        include_json = data.get("include_json", False)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_files = []

        json_file = None
        pdf_file = None

        # =====================================================
        # LOAD LAST SCAN RESULTS FROM DISK (CLI → Flask bridge)
        # =====================================================
        CACHE_PATH = os.path.join(
            os.path.dirname(__file__),
            "last_scan_results.json"
        )

        if not os.path.exists(CACHE_PATH):
            return jsonify({
                "success": False,
                "error": "No scan results found. Please run a scan first."
            }), 400

        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            scan_data = json.load(f)

        findings = scan_data.get("findings", [])
        summary = scan_data.get("summary", [])

        # =====================================================
        # JSON ATTACHMENT
        # =====================================================
        if include_json:
            json_file = os.path.join(
                tempfile.gettempdir(),
                f"report_{timestamp}.json"
            )

            export_to_json(
                findings=findings,
                summary=summary,
                filename=json_file,
                target_url=target_url
            )

            temp_files.append(json_file)

        # =====================================================
        # PDF ATTACHMENT
        # =====================================================
        if include_pdf:
            pdf_file = os.path.join(
                tempfile.gettempdir(),
                f"report_{timestamp}.pdf"
            )

            ok, err = generate_pdf_from_html(html, pdf_file, {
                "summary": summary
            })

            if not ok:
                return jsonify({"success": False, "error": err}), 500

            temp_files.append(pdf_file)

        # =====================================================
        # SEND EMAIL
        # =====================================================
        success = send_report_email(
            recipient_email=recipient_email,
            pdf_file=pdf_file,
            json_file=json_file,
            target_url=target_url,
            sender_email=SENDER_EMAIL,
            sender_password=SENDER_PASSWORD,
            smtp_server=SMTP_SERVER,
            smtp_port=SMTP_PORT
        )

        # Cleanup temp files
        for f in temp_files:
            try:
                os.remove(f)
            except:
                pass

        return jsonify({"success": success})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


# =========================================================
@app.route("/health")
def health():
    return jsonify({
        "weasyprint": WEASYPRINT_AVAILABLE,
        "email_configured": bool(SENDER_EMAIL and SENDER_PASSWORD)
    })

@app.route("/export-json", methods=["POST"])
def export_json_api():
    CACHE_PATH = os.path.join(
        os.path.dirname(__file__),
        "last_scan_results.json"
    )

    if not os.path.exists(CACHE_PATH):
        return jsonify({
            "success": False,
            "error": "No scan results available. Run scan first."
        }), 400

    with open(CACHE_PATH, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    findings = scan_data.get("findings", [])
    summary = scan_data.get("summary", [])

    target_url = (request.get_json() or {}).get("target_url", "Unknown")

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    tmp.close()

    export_to_json(
        findings=findings,
        summary=summary,
        filename=tmp.name,
        target_url=target_url
    )

    return send_file(
        tmp.name,
        as_attachment=True,
        download_name="security_scan_report.json",
        mimetype="application/json"
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)