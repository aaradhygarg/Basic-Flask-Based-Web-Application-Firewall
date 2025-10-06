# 🛡️ Basic Flask-Based Web Application Firewall (WAF)

A lightweight Flask-based Web Application Firewall that monitors and filters incoming HTTP requests to detect and block potential web attacks. It uses rule-based filtering, logs suspicious activities, and provides a simple interface to review blocked or failed requests.

---

## 🚀 Features

- 🧱 Detects and blocks common web attacks (SQL Injection, XSS, etc.)
- 🔍 Logs suspicious or malicious requests in a text file
- 📊 Displays logged requests via an HTML interface
- ✉️ Sends success or failure notifications (mail templates included)
- ⚙️ Simple and extensible Flask-based architecture

---

## 🏗️ Project Structure

```
AaradhyProj/
│
├── app.py                   # Main Flask application file
├── request_logs.txt          # Stores details of blocked/suspicious requests
│
├── templates/                # HTML templates for responses and logs
│   ├── mail_failure.html
│   ├── mail_success.html
│   └── requestlogs.html
```

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/aaradhygarg/Basic-Flask-Based-Web-Application-Firewall
cd Basic Flask Based WAF
```

### 2️⃣ Create a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate       # On Windows: venv\Scripts\activate
```

### 3️⃣ Install Flask
```bash
pip install flask
```

### 4️⃣ Run the Application
```bash
python app.py
```

### 5️⃣ Access in Browser
```
http://127.0.0.1:5000/
```

---

## 🧠 How It Works

1. All HTTP requests are intercepted and analyzed by `app.py`.
2. Request data (parameters, headers, etc.) is checked against predefined patterns.
3. If suspicious activity is detected:
   - The request is blocked.
   - Details are stored in `request_logs.txt`.
   - A failure message is displayed using `mail_failure.html`.
4. Safe requests are allowed and confirmed via `mail_success.html`.
5. Logs can be viewed in `requestlogs.html`.

---

## 🧩 Example Detection Rules

| Attack Type | Example Pattern | Action |
|--------------|----------------|--------|
| SQL Injection | `' OR 1=1 --` | Block |
| XSS | `<script>alert(1)</script>` | Block |
| Command Injection | `; ls` | Block |
| Path Traversal | `../../etc/passwd` | Block |

---

## 🧱 Future Improvements

- Add regex-based rule definitions in a separate config file  
- Implement IP blocking and rate limiting  
- Integrate email alerts for repeated attacks  
- Add authentication for admin log view  
