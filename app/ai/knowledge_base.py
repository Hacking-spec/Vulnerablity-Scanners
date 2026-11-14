"""
Comprehensive Defensive Security Knowledge Base for Offline AI Agent Analysis
"""

SECURITY_KNOWLEDGE_BASE = {
    "sql_injection": {
        "title": "SQL Injection (SQLi) - OWASP Top 10",
        "description": "SQL injection occurs when untrusted user input is directly concatenated into a dynamic database query without proper escaping or parameterization.",
        "risk_impact": "Attackers can bypass authentication, read or modify sensitive data, execute administrative operations, or dump entire database contents.",
        "remediation_steps": [
            "Use parameterized queries (prepared statements) for all database operations.",
            "Utilize object-relational mapping (ORM) libraries like SQLAlchemy, Django ORM, or Prisma.",
            "Apply principle of least privilege to database user credentials.",
            "Avoid string formatting (f-strings, %, or +) when building SQL queries."
        ],
        "code_example": {
            "vulnerable": "query = f\"SELECT * FROM users WHERE username = '{username}' and password = '{password}'\"\ncursor.execute(query)",
            "secure": "query = \"SELECT * FROM users WHERE username = %s AND password = %s\"\ncursor.execute(query, (username, password))"
        }
    },
    "command_injection": {
        "title": "OS Command Injection - CWE-78",
        "description": "Command injection occurs when an application passes unsafe user-supplied data to a system shell (e.g. os.system, subprocess with shell=True).",
        "risk_impact": "Enables arbitrary command execution on the host operating system, potentially leading to full server compromise and lateral movement.",
        "remediation_steps": [
            "Avoid calling system shell commands if native language APIs exist (e.g., use os.listdir instead of 'ls', shutil instead of 'rm').",
            "Set shell=False in subprocess and pass arguments strictly as an array: subprocess.run(['ping', '-c', '1', host])",
            "Enforce strict input whitelisting (alphanumeric only) before passing any parameter to execution."
        ],
        "code_example": {
            "vulnerable": "import os\nos.system(f\"ping -c 1 {user_ip}\")",
            "secure": "import subprocess\n# Strict whitelist or type validation\nsubprocess.run([\"ping\", \"-c\", \"1\", user_ip], shell=False, check=True)"
        }
    },
    "hardcoded_secrets": {
        "title": "Hardcoded Secrets & API Keys - CWE-798",
        "description": "API keys, AWS credentials, database passwords, and cryptographic keys hardcoded directly in source code.",
        "risk_impact": "Anyone with read access to the source code, repository history, or compiled bundle can extract credentials and hijack external services.",
        "remediation_steps": [
            "Immediately revoke and rotate all discovered credentials in their respective service dashboards.",
            "Store secrets in environment variables (.env files) or cloud secret managers (AWS Secrets Manager, HashiCorp Vault).",
            "Add .env and credential files to .gitignore.",
            "Use pre-commit hooks (e.g., git-secrets, detect-secrets, or Gitleaks) to block secrets from being committed."
        ],
        "code_example": {
            "vulnerable": "AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\nSTRIPE_SECRET = \"sk_test_placeholder_secret_key\"",
            "secure": "import os\nfrom dotenv import load_dotenv\nload_dotenv()\n\nAWS_KEY = os.getenv(\"AWS_ACCESS_KEY_ID\")\nSTRIPE_SECRET = os.getenv(\"STRIPE_SECRET_KEY\")"
        }
    },
    "security_headers": {
        "title": "HTTP Security Headers Hardening",
        "description": "Missing defensive HTTP headers that instruct modern web browsers to prevent injection, framing, and transport attacks.",
        "risk_impact": "Enables Clickjacking, Cross-Site Scripting (XSS), MIME-sniffing, and downgrade attacks.",
        "remediation_steps": [
            "Content-Security-Policy (CSP): default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'",
            "Strict-Transport-Security (HSTS): max-age=31536000; includeSubDomains; preload",
            "X-Frame-Options: DENY or SAMEORIGIN",
            "X-Content-Type-Options: nosniff",
            "Referrer-Policy: strict-origin-when-cross-origin",
            "Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ],
        "code_example": {
            "nginx": """server {
    add_header Content-Security-Policy "default-src 'self'; script-src 'self';" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}""",
            "fastapi": """from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

app.add_middleware(SecurityHeadersMiddleware)"""
        }
    },
    "insecure_deserialization": {
        "title": "Insecure Deserialization - CWE-502",
        "description": "Deserializing untrusted data without verification can allow attackers to manipulate application logic, tamper with objects, or achieve Remote Code Execution.",
        "risk_impact": "Remote Code Execution (RCE) via magic methods (__reduce__ in Python pickle, Java gadget chains).",
        "remediation_steps": [
            "Do not accept serialized objects from untrusted sources.",
            "Use safe serialization formats like JSON, MessagePack, or Protocol Buffers.",
            "If using PyYAML, always specify yaml.safe_load(content) instead of yaml.load().",
            "Sign serialized data with HMAC if it must be transmitted across trust boundaries."
        ],
        "code_example": {
            "vulnerable": "import pickle\nuser_data = pickle.loads(untrusted_bytes)",
            "secure": "import json\nuser_data = json.loads(untrusted_string)  # Safe data-only serialization"
        }
    },
    "exposed_ports": {
        "title": "Exposed Network Services & Database Ports",
        "description": "Exposing internal databases (Redis 6379, MongoDB 27017, MySQL 3306, Postgres 5432) or cleartext protocols (Telnet 23, FTP 21) directly to external networks.",
        "risk_impact": "Direct database exposure invites unauthorized credential stuffing, ransomware deletion, or unauthenticated dump.",
        "remediation_steps": [
            "Configure services to bind only to localhost (127.0.0.1) or internal VPC interfaces.",
            "Deploy host-level firewalls (UFW, iptables, Windows Firewall) to restrict inbound connections.",
            "Use SSH tunneling or VPN for administrative remote database access.",
            "Always enable strong password authentication and TLS encryption on database listeners."
        ],
        "code_example": {
            "redis_conf": "# In /etc/redis/redis.conf:\nbind 127.0.0.1\nprotected-mode yes\nrequirepass <StrongRandomPassphrase>",
            "ufw_firewall": "# Allow only local or specific IP to port 5432:\nsudo ufw deny 5432\nsudo ufw allow from 10.0.0.5 to any port 5432"
        }
    },
    "cors_misconfiguration": {
        "title": "Cross-Origin Resource Sharing (CORS) Misconfigurations",
        "description": "Overly permissive CORS rules (e.g. Access-Control-Allow-Origin: * with credentials, or dynamically reflecting untrusted Origin headers).",
        "risk_impact": "Allows malicious websites visited by an authenticated user to perform requests and read sensitive private responses.",
        "remediation_steps": [
            "Avoid wildcard origin (*) if API serves authenticated or sensitive data.",
            "Maintain an explicit whitelist of trusted frontend domains.",
            "Never pair 'Access-Control-Allow-Origin: *' with 'Access-Control-Allow-Credentials: true'."
        ],
        "code_example": {
            "vulnerable": "response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin')\nresponse.headers['Access-Control-Allow-Credentials'] = 'true'",
            "secure": "ALLOWED_ORIGINS = {'https://app.yourdomain.com'}\norigin = request.headers.get('Origin')\nif origin in ALLOWED_ORIGINS:\n    response.headers['Access-Control-Allow-Origin'] = origin\n    response.headers['Access-Control-Allow-Credentials'] = 'true'"
        }
    }
}

