# smtp_test.py
import os, smtplib

SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp-mail.outlook.com")
SMTP_PORT   = int(os.environ.get("SMTP_PORT", 587))
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "websecscan@outlook.com")
SENDER_PASSWORD = os.environ.get("SENDER_PASSWORD", "<your-app-password>")

print("Trying", SMTP_SERVER, SMTP_PORT, "as", SENDER_EMAIL)
try:
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15)
    server.set_debuglevel(1)   # shows SMTP conversation
    server.ehlo()
    server.starttls()
    server.ehlo()
    server.login(SENDER_EMAIL, SENDER_PASSWORD)
    print("Login successful!")
    server.quit()
except Exception as e:
    print("Login failed:", repr(e))
