#email_server.py
"""
Email Server Backend

Simple Flask server to handle email sending requests from the interactive HTML report.
This enables the "Send to Email" feature in the browser-based report.

Usage:
    python email_server.py
    
Then the HTML report can communicate with this server to send emails.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from optional_email import send_report_email
import json
import os
from datetime import datetime
import tempfile
import pdfkit


app = Flask(__name__)
CORS(app)  # Enable CORS for browser requests

# Email configuration (can be set via environment variables)
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))


@app.route('/send-email', methods=['POST'])
def send_email():
    """
    Handle email sending requests from the browser.

    Expected JSON payload:
    {
        "recipient_email": "user@example.com",
        "report_data": {...},             # JSON data (summary + findings)
        "html": "<!doctype>...full html", # OPTIONAL: full report HTML (for faithful PDF)
        "target_url": "https://example.com",
        "include_pdf": true,
        "include_json": true
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        recipient_email = data.get('recipient_email')
        report_data = data.get('report_data')
        html_content_from_client = data.get('html')  # full HTML string (optional)
        target_url = data.get('target_url', 'Unknown')
        include_pdf = bool(data.get('include_pdf', False))
        include_json = bool(data.get('include_json', False))

        if not recipient_email:
            return jsonify({"error": "Recipient email is required"}), 400
        if not include_pdf and not include_json:
            return jsonify({"error": "At least one format (PDF or JSON) must be selected"}), 400

        temp_files = []
        pdf_file = None
        json_file = None

        # Timestamp for file names
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create JSON file if requested
        if include_json and report_data is not None:
            json_file = os.path.join(tempfile.gettempdir(), f'security_report_{timestamp}.json')
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            temp_files.append(json_file)

        # Generate PDF if requested
        if include_pdf:
            try:
                # Prefer HTML from client if provided (faithful rendering)
                if html_content_from_client:
                    html_to_render = html_content_from_client
                else:
                    # Fallback: create a simple HTML page that displays JSON
                    # You can improve styling here to match the report look
                    html_to_render = f"""
                    <html>
                      <head>
                        <meta charset="utf-8"/>
                        <title>Security Report</title>
                        <style>
                          body {{ font-family: Arial, sans-serif; padding: 20px; }}
                          pre {{ white-space: pre-wrap; word-wrap: break-word; background:#f7f7f7; padding:10px; border-radius:4px; }}
                        </style>
                      </head>
                      <body>
                        <h1>Security Report - {target_url}</h1>
                        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <pre>{json.dumps(report_data, indent=2)}</pre>
                      </body>
                    </html>
                    """

                pdf_file = os.path.join(tempfile.gettempdir(), f'security_report_{timestamp}.pdf')

                # If wkhtmltopdf isn't on PATH, uncomment and set the exact path below:
                config = pdfkit.configuration(wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe")
                pdfkit.from_string(html_to_render, pdf_file, configuration=config)

                # Use default config (requires wkhtmltopdf on PATH)
                pdfkit.from_string(html_to_render, pdf_file)
                temp_files.append(pdf_file)
                app.logger.info(f"Generated PDF at {pdf_file}")

            except Exception as e:
                app.logger.exception("Failed to generate PDF")
                # cleanup partial files
                for t in temp_files:
                    try:
                        if os.path.exists(t):
                            os.remove(t)
                    except Exception:
                        pass
                return jsonify({"error": "PDF generation failed", "details": str(e)}), 500

        # Call the existing helper to send email with attachments
        try:
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
        except Exception as e:
            app.logger.exception("Failed to send email")
            # cleanup temporary files
            for t in temp_files:
                try:
                    if os.path.exists(t):
                        os.remove(t)
                except Exception:
                    pass
            return jsonify({"success": False, "error": "Failed to send email", "details": str(e)}), 500

        # Cleanup temp files after successful send
        for t in temp_files:
            try:
                if os.path.exists(t):
                    os.remove(t)
            except Exception:
                app.logger.warning(f"Could not delete temp file {t}")

        if success:
            return jsonify({"success": True, "message": f"Report sent to {recipient_email}"}), 200
        else:
            return jsonify({"success": False, "error": "Failed to send email (SMTP)"}), 500

    except Exception as e:
        app.logger.exception("Unhandled error in /send-email")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "running",
        "service": "WebSecScan Email Server",
        "timestamp": datetime.now().isoformat()
    }), 200


@app.route('/', methods=['GET'])
def index():
    """Root endpoint with instructions."""
    return """
    <html>
    <head>
        <title>WebSecScan Email Server</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background: #f5f5f5;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            h1 { color: #667eea; }
            h2 { color: #2c3e50; margin-top: 20px; }
            code {
                background: #f0f0f0;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: monospace;
            }
            .status {
                display: inline-block;
                padding: 8px 16px;
                background: #28a745;
                color: white;
                border-radius: 20px;
                font-weight: bold;
            }
            pre {
                background: #2c3e50;
                color: #fff;
                padding: 15px;
                border-radius: 5px;
                overflow-x: auto;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ WebSecScan Email Server</h1>
            <p><span class="status">✓ Running</span></p>
            
            <h2>📧 Email Service Status</h2>
            <p>This server handles email sending requests from the WebSecScan interactive reports.</p>
            
            <h2>🔧 Configuration</h2>
            <p>Set these environment variables before running:</p>
            <pre>export SENDER_EMAIL="your-email@gmail.com"
export SENDER_PASSWORD="your-app-password"
export SMTP_SERVER="smtp.gmail.com"  # Optional
export SMTP_PORT="587"  # Optional</pre>
            
            <h2>📝 Gmail Setup Instructions</h2>
            <ol>
                <li>Enable 2-Step Verification in your Google Account</li>
                <li>Generate App Password at: <a href="https://myaccount.google.com/apppasswords" target="_blank">Google App Passwords</a></li>
                <li>Use the App Password (not your regular password)</li>
            </ol>
            
            <h2>🚀 Usage</h2>
            <p>Run the server with:</p>
            <pre>python email_server.py</pre>
            
            <p>Then open your HTML security report in a browser. The "Send to Email" feature will work automatically.</p>
            
            <h2>📡 API Endpoints</h2>
            <ul>
                <li><code>POST /send-email</code> - Send security report via email</li>
                <li><code>GET /health</code> - Health check endpoint</li>
            </ul>
            
            <h2>⚠️ Security Note</h2>
            <p>This is a development server. For production use:</p>
            <ul>
                <li>Use a production WSGI server (gunicorn, uwsgi)</li>
                <li>Add authentication/authorization</li>
                <li>Use HTTPS</li>
                <li>Implement rate limiting</li>
            </ul>
        </div>
    </body>
    </html>
    """

print("SENDER_EMAIL =", SENDER_EMAIL)
print("SMTP_SERVER  =", SMTP_SERVER)
print("SMTP_PORT    =", SMTP_PORT)


def main():
    """Start the email server."""
    print("\n" + "=" * 60)
    print("🛡️  WebSecScan Email Server")
    print("=" * 60)
    
    # Check if email credentials are configured
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        print("\n⚠️  WARNING: Email credentials not configured!")
        print("\nPlease set environment variables:")
        print("  export SENDER_EMAIL='your-email@gmail.com'")
        print("  export SENDER_PASSWORD='your-app-password'")
        print("\nFor Gmail users:")
        print("  1. Enable 2-Step Verification")
        print("  2. Generate App Password at: https://myaccount.google.com/apppasswords")
        print("  3. Use App Password (not regular password)")
        print("\nServer will start, but email sending will prompt for credentials.")
    else:
        print(f"\n✓ Sender email configured: {SENDER_EMAIL}")
        print(f"✓ SMTP server: {SMTP_SERVER}:{SMTP_PORT}")
    
    print("\n" + "=" * 60)
    print("🚀 Starting server on http://localhost:5000")
    print("=" * 60)
    print("\nPress Ctrl+C to stop the server\n")
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)


if __name__ == '__main__':
    main()