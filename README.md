# 🛡️ VulnGuard AI — Vulnerability Scanner & AI Agent Assistant

**VulnGuard AI** is a multi-engine defensive vulnerability scanner and interactive AI cybersecurity assistant built with **FastAPI**, **Python 3**, and a modern web dashboard.

It enables developers, security auditors, and DevOps teams to audit applications across four dimensions and immediately remediate findings using an **AI Agent Chatbot** ("SentinelAI").

---

## 🌟 Key Features

### 1. 🌐 Web & HTTP Security Auditor (Defensive DAST)
- **HTTP Security Headers**: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options (Clickjacking defense), X-Content-Type-Options (nosniff), Referrer-Policy, and Permissions-Policy.
- **SSL/TLS Health**: Certificate expiration date, validity days remaining, issuer verification, and legacy protocol deprecation warnings (TLS 1.0/1.1).
- **Session & Cookie Security**: Audits missing `Secure`, `HttpOnly`, and `SameSite` flags.
- **CORS Audit**: Detects wildcard origins (`*`) and arbitrary origin reflection with credentials.
- **Accidental Information Leaks**: Audits exposed files (`.env`, `.git/HEAD`, `robots.txt`, database backups).

### 2. 💻 Source Code & Secret Scanner (SAST)
- **Hardcoded Secrets & API Keys**: Scans for AWS Access Keys, Stripe Live Keys, GitHub Tokens, Private Keys (RSA/SSH), Database Connection URIs with passwords, and generic auth tokens.
- **Code Injection & Dangerous APIs**: Flags Command Injection (`os.system`, `subprocess(shell=True)`), Dynamic Code Execution (`eval`, `exec`), and DOM XSS.
- **SQL Injection**: Detects unsafe query formatting (`f"SELECT ... {var}"`, string concatenation).
- **Insecure Deserialization**: Flags dangerous calls (`pickle.loads`, `yaml.load` without SafeLoader).
- **Cryptographic Weaknesses**: Flags broken algorithms (`MD5`, `SHA1` for passwords, `ECB` cipher mode).
- **Framework Hardening**: Flags `DEBUG=True`, `ALLOWED_HOSTS=['*']`, and `verify=False`.

### 3. 🔌 Defensive Network & Port Auditor
- Audits network host ports and detects exposed internal services:
  - Database ports (`3306` MySQL, `5432` PostgreSQL, `6379` Redis, `27017` MongoDB, `9200` Elasticsearch)
  - Cleartext legacy protocols (`21` FTP, `23` Telnet, `110` POP3, `143` IMAP)
  - Remote desktop exposure (`3389` RDP)
- Fast multi-threaded socket probes with strict timeouts.

### 4. 📦 Software Composition Analysis (SCA)
- Audits Python `requirements.txt` and Node.js `package.json`.
- Compares installed package versions against an advisory CVE database with CVSS scores and safe upgrade targets.

### 5. 🤖 SentinelAI Security Agent Chatbot
- **Context-Aware**: Directly reads the current scan's findings, file paths, line numbers, and evidence snippets.
- **One-Click Remediation**: Click **"Ask AI to Fix"** on any finding to instantly generate step-by-step remediation instructions and secure code patches.
- **Multi-Engine Intelligence**:
  - **Offline Security Expert**: Works instantly out-of-the-box with zero API keys or external dependencies.
  - **Live LLM Support**: Switch between **Google Gemini (Gemini 2.5 Flash)**, **OpenAI (GPT-4o-mini)**, or **Groq (LLaMA-3.3-70B)** directly via the UI settings modal.
- **Pre-loaded Quick Actions**: One-click prompts for fixing highest-risk items, generating Nginx/FastAPI security headers, preventing SQL injection, and securing secrets.

### 6. 📊 Modern Cyber Dashboard & Reports
- Real-time Risk Score calculation ($0 - 100$).
- Severity breakdown: Critical, High, Medium, Low, Info.
- Interactive severity filter (All, Critical, High, Medium, Low).
- One-click report export to **HTML** (printable/shareable) or **JSON**.

---

## 🚀 Quick Start

### 1. Launch the Application
Run the launcher from the project directory:
```bash
python run.py
```

The server will start on:
👉 **[http://localhost:8000](http://localhost:8000)**

Open this URL in your web browser.

---

## 🧪 Testing the Scanners (1-Click Demos)

1. **Source Code Scanner**:
   - Navigate to the **Code / SAST** tab.
   - Click **"Load Sample Vulnerable Code"**.
   - Click **"Scan Source Code"**.
   - Review findings (AWS secret key, SQL injection, OS command injection, pickle deserialization, MD5, verify=False).
   - Click **"Ask AI to Fix"** on any finding to watch SentinelAI provide the remediation code!

2. **Dependency Scanner**:
   - Navigate to the **Dependencies** tab.
   - Click **"Load Sample requirements.txt"**.
   - Click **"Check Dependencies for CVEs"**.
   - Review reported CVEs (e.g. `CVE-2023-32681` in requests, `CVE-2020-14343` in PyYAML).

3. **Web Security Auditor**:
   - Navigate to the **Web Auditor** tab.
   - Enter any web endpoint (e.g., `https://example.com`) and click **"Run Web Audit"**.
   - Inspect security headers, SSL status, and cookie attributes.

4. **Port Auditor**:
   - Navigate to the **Port Auditor** tab.
   - Enter `127.0.0.1` and click **"Audit Open Ports"**.

---

## 📁 Project Architecture

```
c:\Application\Downloads\Vulnerablity Scanner\
├── app/
│   ├── __init__.py
│   ├── main.py                     # FastAPI application & REST endpoints
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── web_scanner.py          # HTTP headers, SSL/TLS, CORS, cookies auditor
│   │   ├── code_scanner.py         # Static code analysis & secrets detection
│   │   ├── port_scanner.py         # Defensive network port auditor
│   │   └── dependency_scanner.py   # Software composition analysis (SCA)
│   ├── ai/
│   │   ├── __init__.py
│   │   ├── agent.py                # SentinelAI agent (Offline & Cloud LLM support)
│   │   └── knowledge_base.py       # Defensive security remediation knowledge base
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py              # Pydantic data schemas
│   └── static/
│       ├── index.html              # Cyber-themed modern dashboard
│       ├── css/
│       │   └── style.css           # Styling & animations
│       └── js/
│           ├── app.js              # UI controller & scanner logic
│           └── chat.js             # AI Chatbot interactive drawer
├── run.py                          # Main entry point launcher
├── test_scanner.py                 # Self-verification test suite
├── requirements.txt                # Python package requirements
└── README.md                       # Documentation
```

---

## 🔒 Security & Safe Usage Notice
VulnGuard AI is engineered strictly for **defensive security auditing, static code analysis, and educational remediation**. It does not produce weaponized exploits or offensive attack payloads.

