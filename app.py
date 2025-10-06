from flask import Flask, request, render_template, redirect, url_for
import re
import urllib.parse
from email.mime.text import MIMEText
from email.header import Header
import smtplib
from datetime import datetime
import os

app = Flask(__name__)

# === Email Configuration ===
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SENDER_EMAIL = 'reachingag@gmail.com'
SENDER_PASSWORD = 'fzshzwtxbzwhgpal'
RECIPIENT_EMAIL = 'garg.aaradhy@outlook.com'

# === Local Log File ===
LOG_FILE = "request_logs.txt"

# === Threat Patterns ===
THREAT_PATTERNS = {
    "SQL Injection": re.compile(
        r"(?:')|(?:--)|(/\*(?:.|[\n\r])*?\*/)|"
        r"\b(SELECT|UPDATE|DELETE|INSERT|DROP|UNION|ALTER|CREATE|WHERE|HAVING|OR|AND|EXEC|XP_CMDSHELL)\b",
        re.IGNORECASE
    ),
    "XSS": re.compile(
        r"(<script.*?>.*?</script>)|(<.*?on\w+\s*=\s*['\"].*?>)|(javascript:)|(&#x?[0-9a-f]+;)",
        re.IGNORECASE
    ),
    "Command Injection": re.compile(
        r"(;|&&|\|\||`|\$\(|\|)",
        re.IGNORECASE
    ),
    "Path Traversal": re.compile(
        r"(\.\./|\.\.\\)",
        re.IGNORECASE
    ),
    "DOS Payload": re.compile(
        r"(sleep\((\s*[0-9]+\s*)\))|benchmark\((.*?)\)",
        re.IGNORECASE
    )
}

# === Log to File ===
def log_to_file(method, uri, query, ip, blocked):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "BLOCKED" if blocked else "ALLOWED"
    entry = f"{timestamp} | {ip} | {method} {uri}?{query} | {status}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)

# === Send Email Alert ===
def send_alert(method, uri, query, ip):
    subject = "🚨 WebAppFirewall Alert - Suspicious Request"
    body = f"""Suspicious request detected:\n\nMethod: {method}\nURI: {uri}\nQuery: {query}\nIP Address: {ip}"""

    msg = MIMEText(body, _charset='utf-8')
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECIPIENT_EMAIL
    msg['Subject'] = Header(subject, 'utf-8')

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"[ALERT] Email Failed: {e}")
        return False

# === Security Filter Middleware ===
@app.before_request
def security_filter():
    # Skip security check for internal safe routes
    safe_routes = ["/mail_success", "/mail_failure", "/requestlogs", "/favicon.ico"]
    if request.path in safe_routes:
        return  # Allow through without scanning

    raw_query = request.query_string.decode('utf-8')
    decoded_query = urllib.parse.unquote(raw_query)
    uri = request.path
    ip = request.remote_addr
    method = request.method

    if decoded_query:  # Only scan if query string exists
        for threat_type, pattern in THREAT_PATTERNS.items():
            if pattern.search(decoded_query):
                log_to_file(method, uri, decoded_query, ip, blocked=True)
                success = send_alert(method, uri, decoded_query, ip)
                return redirect(url_for('mail_success' if success else 'mail_failure'))

    log_to_file(method, uri, decoded_query, ip, blocked=False)

# === Routes ===
@app.route('/')
def index():
    return "✅ Welcome to the secure Python WAF (No DB)!"

@app.route('/mail_success')
def mail_success():
    return render_template('mail_success.html')

@app.route('/mail_failure')
def mail_failure():
    return render_template('mail_failure.html')

@app.route('/requestlogs')
def request_logs():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = f.readlines()
    return render_template('requestlogs.html', logs=logs)

# === Run App ===
if __name__ == "__main__":
    app.run(debug=True)
