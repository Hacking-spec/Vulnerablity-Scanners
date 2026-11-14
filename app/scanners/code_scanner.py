import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from app.models.schemas import VulnerabilityFinding, SeverityLevel

# Rule definition: Pattern, Title, Severity, Category, Description, CWE, Remediation, CVSS
SAST_RULES = [
    # 1. Hardcoded Secrets & Credentials
    {
        "id": "SEC-AWS-KEY",
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "title": "Hardcoded AWS Access Key ID Detected",
        "severity": SeverityLevel.CRITICAL,
        "category": "Hardcoded Secrets",
        "description": "An Amazon Web Services (AWS) Access Key ID was detected in source code. If exposed, attackers can access your AWS cloud resources.",
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "remediation": "Revoke the exposed key immediately in AWS IAM. Use AWS Secrets Manager, IAM Roles, or environment variables (.env) instead of committing credentials.",
        "cvss": 9.8
    },
    {
        "id": "SEC-PRIVATE-KEY",
        "pattern": r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----",
        "title": "Unencrypted Private Key in Source Code",
        "severity": SeverityLevel.CRITICAL,
        "category": "Cryptographic Secrets",
        "description": "A private cryptographic key block was found committed to the source file. Anyone with repository access can decrypt communications or forge signatures.",
        "cwe": "CWE-321: Use of Hard-coded Cryptographic Key",
        "remediation": "Remove the private key file/block from version control immediately, rotate the key pair, and load keys via a secure vault or filesystem permission-controlled paths.",
        "cvss": 9.5
    },
    {
        "id": "SEC-GITHUB-TOKEN",
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
        "title": "Hardcoded GitHub Personal Access Token",
        "severity": SeverityLevel.CRITICAL,
        "category": "Hardcoded Secrets",
        "description": "A GitHub personal access token was discovered. Attackers can clone private repositories, inject malicious commits, or access GitHub actions secrets.",
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "remediation": "Revoke and regenerate the GitHub token from your GitHub settings immediately. Store tokens as GitHub Secrets or environment variables.",
        "cvss": 9.2
    },
    {
        "id": "SEC-STRIPE-KEY",
        "pattern": r"sk_live_[0-9a-zA-Z]{24,34}",
        "title": "Hardcoded Stripe Live Secret Key",
        "severity": SeverityLevel.CRITICAL,
        "category": "Payment & Financial Secrets",
        "description": "A live Stripe API Secret Key was found in source code. This grants full programmatic control over live payment charges and financial data.",
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "remediation": "Roll the secret key immediately in the Stripe Dashboard and ensure the code reads secrets from environment variables or a key management system.",
        "cvss": 9.8
    },
    {
        "id": "SEC-DB-URI-CREDENTIALS",
        "pattern": r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^:\s\"']+:[^@\s\"']+@[^\s\"']+",
        "title": "Database Connection String with Plaintext Credentials",
        "severity": SeverityLevel.HIGH,
        "category": "Database Credentials",
        "description": "Database connection URI containing embedded username and password was found in plaintext.",
        "cwe": "CWE-256: Plaintext Storage of a Password",
        "remediation": "Separate credentials from code using DATABASE_URL environment variables or a secret vault.",
        "cvss": 8.5
    },
    {
        "id": "SEC-HARDCODED-PASSWORD",
        "pattern": r"""(?i)(?:password|passwd|api_secret|client_secret|auth_token)\s*=\s*['"][^'"]{6,}['"]""",
        "title": "Potential Hardcoded Password or Secret Assignment",
        "severity": SeverityLevel.HIGH,
        "category": "Hardcoded Secrets",
        "description": "Detected hardcoded password or auth secret assigned as a literal string in the code.",
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "remediation": "Externalize all credentials into environment variables or .env files excluded via .gitignore.",
        "cvss": 8.0
    },

    # 2. Command & Code Injection
    {
        "id": "CODE-COMMAND-INJECTION",
        "pattern": r"(?:os\.system|os\.popen|subprocess\.(?:call|Popen|run)\s*\([^)]*shell\s*=\s*True)",
        "title": "Potential OS Command Injection Risk",
        "severity": SeverityLevel.CRITICAL,
        "category": "Command Injection",
        "description": "Use of system shell execution (shell=True or os.system) can allow arbitrary command execution if unsanitized user input is concatenated into the command.",
        "cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
        "remediation": "Avoid shell=True. Pass command arguments as a list to subprocess.run(['cmd', arg1, arg2]) and validate all parameters against a strict whitelist.",
        "cvss": 9.8
    },
    {
        "id": "CODE-EVAL-EXEC",
        "pattern": r"\b(?:eval|exec)\s*\([^)]*\)",
        "title": "Arbitrary Code Execution via eval() or exec()",
        "severity": SeverityLevel.HIGH,
        "category": "Code Execution",
        "description": "Dynamic execution of string code via eval() or exec() is dangerous and frequently leads to Remote Code Execution (RCE) if user input reaches it.",
        "cwe": "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
        "remediation": "Replace dynamic eval with safe alternatives like ast.literal_eval for data parsing, or dispatch tables for dynamic functions.",
        "cvss": 8.8
    },

    # 3. SQL Injection Patterns
    {
        "id": "CODE-SQL-INJECTION-FSTRING",
        "pattern": r"""(?i)f["'].*?\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*?\{[^}\n]+\}.*?["']""",
        "title": "SQL Injection: Formatted f-string in SQL Query",
        "severity": SeverityLevel.CRITICAL,
        "category": "SQL Injection",
        "description": "Constructing SQL queries using f-strings or string concatenation bypasses database query parameterization and allows SQL Injection attacks.",
        "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        "remediation": "Use parameterized queries or ORM query builders. For example: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "cvss": 9.4
    },
    {
        "id": "CODE-SQL-INJECTION-CONCAT",
        "pattern": r"""(?i)["'].*?\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*?["']\s*\+""",
        "title": "SQL Injection: String Concatenation in Query",
        "severity": SeverityLevel.HIGH,
        "category": "SQL Injection",
        "description": "Query is concatenated using the '+' operator, which is susceptible to SQL injection.",
        "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        "remediation": "Always pass parameters as query parameters rather than concatenating strings.",
        "cvss": 8.9
    },

    # 4. Insecure Deserialization
    {
        "id": "CODE-INSECURE-DESERIALIZATION-PICKLE",
        "pattern": r"\bpickle\.(?:loads|load)\s*\(",
        "title": "Insecure Deserialization via Python pickle",
        "severity": SeverityLevel.HIGH,
        "category": "Insecure Deserialization",
        "description": "The pickle module is not secure against erroneous or maliciously constructed data. Unpickling untrusted data allows arbitrary Python code execution.",
        "cwe": "CWE-502: Deserialization of Untrusted Data",
        "remediation": "Never use pickle with untrusted data. Use safer serialization formats such as JSON or Protocol Buffers.",
        "cvss": 8.8
    },
    {
        "id": "CODE-INSECURE-YAML-LOAD",
        "pattern": r"\byaml\.load\s*\([^)]*(?!Loader=yaml\.SafeLoader|Loader=SafeLoader)[^)]*\)",
        "title": "Unsafe YAML Deserialization (yaml.load without SafeLoader)",
        "severity": SeverityLevel.HIGH,
        "category": "Insecure Deserialization",
        "description": "Using yaml.load without specifying SafeLoader allows arbitrary Python object instantiation and code execution.",
        "cwe": "CWE-502: Deserialization of Untrusted Data",
        "remediation": "Use yaml.safe_load(data) or specify Loader=yaml.SafeLoader.",
        "cvss": 8.6
    },

    # 5. Weak Cryptography & Hashing
    {
        "id": "CRYPTO-WEAK-HASH-MD5",
        "pattern": r"hashlib\.(?:md5|sha1)\s*\(",
        "title": "Use of Broken or Weak Hash Algorithm (MD5/SHA1)",
        "severity": SeverityLevel.MEDIUM,
        "category": "Weak Cryptography",
        "description": "MD5 and SHA1 suffer from known collision attacks and should never be used for security purposes, digital signatures, or password storage.",
        "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        "remediation": "Use SHA-256 (hashlib.sha256()) for general hashing. For password hashing, use dedicated slow KDFs such as Argon2id, bcrypt, or scrypt.",
        "cvss": 5.9
    },
    {
        "id": "CRYPTO-INSECURE-CIPHER-MODE",
        "pattern": r"MODE_ECB\b",
        "title": "Insecure Cipher Mode (Electronic Codebook - ECB)",
        "severity": SeverityLevel.HIGH,
        "category": "Weak Cryptography",
        "description": "ECB mode does not provide serious pattern confidentiality; identical plaintext blocks result in identical ciphertext blocks.",
        "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        "remediation": "Use authenticated encryption modes such as AES-GCM or ChaCha20-Poly1305.",
        "cvss": 7.5
    },

    # 6. Misconfigurations & Insecure Defaults
    {
        "id": "CONFIG-SSL-VERIFY-DISABLED",
        "pattern": r"verify\s*=\s*False\b",
        "title": "SSL Certificate Verification Disabled (verify=False)",
        "severity": SeverityLevel.HIGH,
        "category": "Insecure Transport",
        "description": "Disabling TLS certificate verification in HTTP requests exposes all traffic to trivial interception and Man-in-the-Middle (MitM) spoofing.",
        "cwe": "CWE-295: Improper Certificate Validation",
        "remediation": "Remove 'verify=False' and ensure valid CA certificates are present in the trust store.",
        "cvss": 7.4
    },
    {
        "id": "CONFIG-DEBUG-TRUE",
        "pattern": r"""(?:DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True)""",
        "title": "Framework Debug Mode Enabled in Code",
        "severity": SeverityLevel.MEDIUM,
        "category": "Configuration Misconfiguration",
        "description": "Running in Debug mode in production exposes interactive debuggers (e.g. Werkzeug console) and detailed stack traces disclosing internal code paths.",
        "cwe": "CWE-489: Active Debug Code",
        "remediation": "Ensure DEBUG is controlled via an environment variable and defaults to False in production environments.",
        "cvss": 6.5
    },
    {
        "id": "CONFIG-PERMISSIVE-HOST",
        "pattern": r"""(?:ALLOWED_HOSTS\s*=\s*\[['"]\*['"]\]|host\s*=\s*['"]0\.0\.0\.0['"])""",
        "title": "Permissive Host Binding or Wildcard Host Header",
        "severity": SeverityLevel.LOW,
        "category": "Network Configuration",
        "description": "Binding to '0.0.0.0' exposes the service on all network interfaces. Wildcard ALLOWED_HOSTS enables HTTP Host Header poisoning attacks.",
        "cwe": "CWE-183: Permissive List of Allowed Inputs",
        "remediation": "Bind only to localhost (127.0.0.1) in development, and specify explicit trusted domain names in ALLOWED_HOSTS.",
        "cvss": 3.9
    },

    # 7. Web Frontend XSS (DOM XSS)
    {
        "id": "FRONTEND-DOM-XSS-INNERHTML",
        "pattern": r"""\b(?:innerHTML|outerHTML)\s*=\s*(?!['"][^'"]*['"])[a-zA-Z0-9_\.]+""",
        "title": "Potential DOM-Based XSS via innerHTML Assignment",
        "severity": SeverityLevel.HIGH,
        "category": "Cross-Site Scripting (XSS)",
        "description": "Direct assignment of variables to innerHTML can lead to DOM-based Cross-Site Scripting if the content originated from untrusted sources or URL parameters.",
        "cwe": "CWE-79: Cross-site Scripting",
        "remediation": "Use textContent or innerText instead of innerHTML, or sanitize content with DOMPurify before insertion.",
        "cvss": 7.5
    }
]

class CodeSecurityScanner:
    def __init__(self):
        self.rules = SAST_RULES
        # Compile regexes for speed
        self.compiled_rules = []
        for r in self.rules:
            self.compiled_rules.append({
                **r,
                "regex": re.compile(r["pattern"])
            })

    def scan_content(self, content: str, file_name: str = "snippet.py") -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            # Skip pure comments to reduce noise
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*"):
                # Still check for secrets in comments!
                if not any(k in stripped.lower() for k in ["key", "secret", "token", "password"]):
                    continue

            for rule in self.compiled_rules:
                matches = list(rule["regex"].finditer(line))
                if matches:
                    # Obfuscate matched secrets in evidence
                    evidence_line = line.strip()
                    if "Secret" in rule["category"] or "Credentials" in rule["category"]:
                        # Mask the middle of the match
                        for m in matches:
                            val = m.group(0)
                            if len(val) > 8:
                                masked = val[:4] + "*" * (len(val) - 8) + val[-4:]
                                evidence_line = evidence_line.replace(val, masked)

                    findings.append(VulnerabilityFinding(
                        id=f"{rule['id']}-L{line_idx}",
                        title=rule["title"],
                        severity=rule["severity"],
                        category=rule["category"],
                        description=rule["description"],
                        evidence=f"Line {line_idx}: {evidence_line[:150]}",
                        file_path=file_name,
                        line_number=line_idx,
                        cwe=rule["cwe"],
                        remediation=rule["remediation"],
                        cvss_score=rule["cvss"]
                    ))

        return findings

    def scan_directory(self, dir_path: str, max_files: int = 250) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        p = Path(dir_path)
        if not p.exists() or not p.is_dir():
            return [VulnerabilityFinding(
                id="SCAN-INVALID-DIR",
                title="Directory Not Found",
                severity=SeverityLevel.INFO,
                category="File System",
                description=f"The specified directory does not exist or is not readable: {dir_path}",
                evidence=dir_path,
                remediation="Provide a valid, accessible directory path.",
                cvss_score=0.0
            )]

        # Ignored directories
        ignore_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", ".idea", ".vscode", "dist", "build"}
        valid_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".html", ".env", ".json", ".yaml", ".yml", ".sql", ".sh", ".dockerfile"}

        scanned_count = 0
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for file in files:
                if scanned_count >= max_files:
                    break

                file_ext = Path(file).suffix.lower()
                if file.lower() == "dockerfile" or file.startswith(".env") or file_ext in valid_exts:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, dir_path)
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            file_findings = self.scan_content(content, file_name=rel_path)
                            findings.extend(file_findings)
                            scanned_count += 1
                    except Exception:
                        pass

        return findings

