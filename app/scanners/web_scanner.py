import ssl
import socket
import urllib.parse
from datetime import datetime, timezone
import requests
from typing import List, Tuple
from app.models.schemas import VulnerabilityFinding, SeverityLevel

class WebSecurityAuditor:
    def __init__(self, timeout: int = 7):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnGuard-Auditor/1.0 (Defensive Security Scanner; +https://vulnguard.local)"
        })

    def normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
        return url

    def scan(self, target_url: str, check_ssl: bool = True, check_headers: bool = True,
             check_sensitive_paths: bool = True, check_cors: bool = True) -> List[VulnerabilityFinding]:
        target_url = self.normalize_url(target_url)
        findings: List[VulnerabilityFinding] = []
        parsed = urllib.parse.urlparse(target_url)
        hostname = parsed.hostname or target_url
        is_https = parsed.scheme == "https"

        # 1. SSL/TLS Audit
        if is_https and check_ssl:
            ssl_findings = self._audit_ssl(hostname, parsed.port or 443)
            findings.extend(ssl_findings)
        elif not is_https:
            findings.append(VulnerabilityFinding(
                id="WEB-CLEARTEXT-HTTP",
                title="Unencrypted Cleartext HTTP Protocol in Use",
                severity=SeverityLevel.HIGH,
                category="Transport Layer Security",
                description="The website is served over plaintext HTTP without SSL/TLS encryption. Traffic can be intercepted or manipulated via man-in-the-middle (MitM) attacks.",
                evidence=f"URL scheme is {parsed.scheme}://",
                url=target_url,
                cwe="CWE-319: Cleartext Transmission of Sensitive Information",
                remediation="Enforce HTTPS across all pages and configure automatic 301 Permanent Redirects from HTTP to HTTPS with HSTS.",
                cvss_score=7.4
            ))

        # 2. Web Response & Headers Audit
        try:
            resp = self.session.get(target_url, timeout=self.timeout, allow_redirects=True, verify=False)
            
            if check_headers:
                header_findings = self._audit_headers(resp, target_url)
                findings.extend(header_findings)

            if check_cors:
                cors_findings = self._audit_cors(target_url)
                findings.extend(cors_findings)

            if check_sensitive_paths:
                path_findings = self._audit_sensitive_paths(target_url)
                findings.extend(path_findings)

        except requests.exceptions.RequestException as e:
            findings.append(VulnerabilityFinding(
                id="WEB-CONNECTION-ERROR",
                title="Target Connection Warning",
                severity=SeverityLevel.INFO,
                category="Availability / Connectivity",
                description=f"Could not complete full HTTP inspection: {str(e)}",
                evidence=str(e),
                url=target_url,
                cwe="CWE-699",
                remediation="Ensure the host is online, reachable, and DNS is resolvable.",
                cvss_score=0.0
            ))

        return findings

    def _audit_ssl(self, hostname: str, port: int) -> List[VulnerabilityFinding]:
        findings = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Check TLS version
                    if version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                        findings.append(VulnerabilityFinding(
                            id="SSL-DEPRECATED-PROTOCOL",
                            title=f"Deprecated TLS Protocol In Use: {version}",
                            severity=SeverityLevel.HIGH,
                            category="SSL/TLS Security",
                            description=f"The server accepted connection using deprecated protocol {version}, which suffers from known cryptographic weaknesses.",
                            evidence=f"Negotiated version: {version}, Cipher: {cipher[0] if cipher else 'Unknown'}",
                            cwe="CWE-326: Inadequate Encryption Strength",
                            remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 in web server configuration. Enforce TLS 1.2 and TLS 1.3 exclusively.",
                            cvss_score=7.5
                        ))

                    # Check certificate expiry
                    if cert and "notAfter" in cert:
                        # Format example: 'May  4 12:00:00 2026 GMT'
                        expire_str = cert["notAfter"]
                        try:
                            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            days_remaining = (expire_dt - now).days
                            if days_remaining < 0:
                                findings.append(VulnerabilityFinding(
                                    id="SSL-CERT-EXPIRED",
                                    title="SSL/TLS Certificate Has Expired",
                                    severity=SeverityLevel.CRITICAL,
                                    category="SSL/TLS Security",
                                    description=f"The SSL certificate expired {abs(days_remaining)} days ago on {expire_str}.",
                                    evidence=f"Expired on: {expire_str}",
                                    cwe="CWE-295: Improper Certificate Validation",
                                    remediation="Immediately renew and deploy a valid SSL/TLS certificate.",
                                    cvss_score=9.1
                                ))
                            elif days_remaining <= 14:
                                findings.append(VulnerabilityFinding(
                                    id="SSL-CERT-EXPIRING-SOON",
                                    title=f"SSL/TLS Certificate Expiring Soon ({days_remaining} days remaining)",
                                    severity=SeverityLevel.MEDIUM,
                                    category="SSL/TLS Security",
                                    description=f"The SSL certificate will expire on {expire_str} ({days_remaining} days left).",
                                    evidence=f"Valid until: {expire_str}",
                                    cwe="CWE-295",
                                    remediation="Renew certificate prior to expiration to avoid user disruption.",
                                    cvss_score=5.3
                                ))
                        except Exception:
                            pass
        except ssl.SSLCertVerificationError as e:
            findings.append(VulnerabilityFinding(
                id="SSL-CERT-VERIFICATION-FAILED",
                title="SSL Certificate Verification Failed (Untrusted or Self-Signed)",
                severity=SeverityLevel.HIGH,
                category="SSL/TLS Security",
                description=f"The SSL certificate could not be verified by trust store: {str(e)}",
                evidence=str(e),
                cwe="CWE-295: Improper Certificate Validation",
                remediation="Ensure certificate is issued by a recognized Certificate Authority (CA) and full certificate chain is provided.",
                cvss_score=7.5
            ))
        except Exception as e:
            # Non-blocking socket/SSL errors
            pass
        return findings

    def _audit_headers(self, resp: requests.Response, target_url: str) -> List[VulnerabilityFinding]:
        findings = []
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Content-Security-Policy
        if "content-security-policy" not in headers:
            findings.append(VulnerabilityFinding(
                id="HEADER-MISSING-CSP",
                title="Missing Content-Security-Policy (CSP) Header",
                severity=SeverityLevel.HIGH,
                category="Security Headers",
                description="Content Security Policy (CSP) header is missing. CSP helps detect and mitigate Cross-Site Scripting (XSS), clickjacking, and data injection attacks.",
                evidence="Header 'Content-Security-Policy' not found in server response.",
                url=target_url,
                cwe="CWE-693: Protection Mechanism Failure",
                remediation="Configure a restrictive Content-Security-Policy header. Example: default-src 'self'; script-src 'self'; object-src 'none';",
                cvss_score=6.8
            ))
        else:
            csp_val = headers["content-security-policy"]
            if "'unsafe-inline'" in csp_val and "'nonce-" not in csp_val and "'sha256-" not in csp_val:
                findings.append(VulnerabilityFinding(
                    id="HEADER-WEAK-CSP-INLINE",
                    title="Weak CSP: 'unsafe-inline' Permitted in Script Directive",
                    severity=SeverityLevel.MEDIUM,
                    category="Security Headers",
                    description="The CSP policy includes 'unsafe-inline' without cryptographic nonce or hashes, weakening protection against Cross-Site Scripting (XSS).",
                    evidence=f"CSP: {csp_val[:100]}...",
                    url=target_url,
                    cwe="CWE-79: Cross-site Scripting",
                    remediation="Remove 'unsafe-inline' from script-src and adopt cryptographic nonces or SHA hashes for inline scripts.",
                    cvss_score=5.5
                ))

        # Strict-Transport-Security (HSTS)
        if target_url.startswith("https://") and "strict-transport-security" not in headers:
            findings.append(VulnerabilityFinding(
                id="HEADER-MISSING-HSTS",
                title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                severity=SeverityLevel.MEDIUM,
                category="Security Headers",
                description="HSTS ensures modern browsers interact with the server only over secure HTTPS connections, protecting against SSL-stripping man-in-the-middle attacks.",
                evidence="Header 'Strict-Transport-Security' not found.",
                url=target_url,
                cwe="CWE-523: Unprotected Transport",
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                cvss_score=5.9
            ))

        # X-Frame-Options
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            findings.append(VulnerabilityFinding(
                id="HEADER-MISSING-X-FRAME-OPTIONS",
                title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                severity=SeverityLevel.MEDIUM,
                category="Security Headers",
                description="X-Frame-Options or CSP frame-ancestors is missing, which could allow malicious sites to embed this page in an iframe and execute Clickjacking attacks.",
                evidence="Header 'X-Frame-Options' not found.",
                url=target_url,
                cwe="CWE-1021: Improper Restriction of Rendered UI Layers (Clickjacking)",
                remediation="Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors 'self''.",
                cvss_score=5.4
            ))

        # X-Content-Type-Options
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append(VulnerabilityFinding(
                id="HEADER-MISSING-NOSNIFF",
                title="Missing X-Content-Type-Options: nosniff Header",
                severity=SeverityLevel.LOW,
                category="Security Headers",
                description="Without 'X-Content-Type-Options: nosniff', browsers may perform MIME-type sniffing, treating non-executable MIME types as executable script content.",
                evidence=f"Value: '{headers.get('x-content-type-options', 'None')}'",
                url=target_url,
                cwe="CWE-79: Cross-site Scripting",
                remediation="Set 'X-Content-Type-Options: nosniff' header.",
                cvss_score=3.7
            ))

        # Referrer-Policy
        if "referrer-policy" not in headers:
            findings.append(VulnerabilityFinding(
                id="HEADER-MISSING-REFERRER-POLICY",
                title="Missing Referrer-Policy Header",
                severity=SeverityLevel.LOW,
                category="Security Headers",
                description="Without an explicit Referrer-Policy, sensitive URL path parameters or query tokens may leak to third-party domains in the HTTP Referer header.",
                evidence="Header 'Referrer-Policy' not found.",
                url=target_url,
                cwe="CWE-200: Exposure of Sensitive Information",
                remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                cvss_score=3.1
            ))

        # Information Disclosure (Server / X-Powered-By)
        server_val = headers.get("server")
        if server_val and any(char.isdigit() for char in server_val):
            findings.append(VulnerabilityFinding(
                id="INFO-SERVER-VERSION-DISCLOSURE",
                title="Web Server Version Information Disclosure",
                severity=SeverityLevel.LOW,
                category="Information Disclosure",
                description=f"Server header exposes specific product version ({server_val}). This assists attackers in fingerprinting known software vulnerabilities.",
                evidence=f"Server: {server_val}",
                url=target_url,
                cwe="CWE-200: Exposure of Sensitive Information",
                remediation="Configure server to suppress version tokens (e.g., 'ServerTokens Prod' in Apache or 'server_tokens off;' in NGINX).",
                cvss_score=3.3
            ))

        powered_by = headers.get("x-powered-by")
        if powered_by:
            findings.append(VulnerabilityFinding(
                id="INFO-X-POWERED-BY-DISCLOSURE",
                title="Technology Stack Fingerprint (X-Powered-By)",
                severity=SeverityLevel.LOW,
                category="Information Disclosure",
                description=f"Application discloses backend technology stack via X-Powered-By header ({powered_by}).",
                evidence=f"X-Powered-By: {powered_by}",
                url=target_url,
                cwe="CWE-200: Exposure of Sensitive Information",
                remediation="Disable the X-Powered-By header in application framework settings (e.g. app.disable('x-powered-by') in Express).",
                cvss_score=2.6
            ))

        # Cookie Security Audit
        for cookie in resp.cookies:
            cookie_issues = []
            if not cookie.secure and target_url.startswith("https://"):
                cookie_issues.append("Missing 'Secure' flag")
            if not cookie.has_nonstandard_attr("httponly") and not getattr(cookie, "_rest", {}).get("httponly"):
                cookie_issues.append("Missing 'HttpOnly' flag")
            
            samesite = getattr(cookie, "_rest", {}).get("samesite")
            if not samesite:
                cookie_issues.append("Missing 'SameSite' attribute")

            if cookie_issues:
                findings.append(VulnerabilityFinding(
                    id=f"COOKIE-INSECURE-{cookie.name.upper()}",
                    title=f"Insecure Cookie Configuration: '{cookie.name}'",
                    severity=SeverityLevel.MEDIUM if "Secure" in " ".join(cookie_issues) else SeverityLevel.LOW,
                    category="Session & Cookie Security",
                    description=f"Cookie '{cookie.name}' was set with insecure flags: {', '.join(cookie_issues)}.",
                    evidence=f"Cookie name={cookie.name}; domain={cookie.domain}; flags={cookie_issues}",
                    url=target_url,
                    cwe="CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                    remediation=f"Configure cookie '{cookie.name}' with 'Secure; HttpOnly; SameSite=Lax' (or 'SameSite=Strict').",
                    cvss_score=5.0
                ))

        return findings

    def _audit_cors(self, target_url: str) -> List[VulnerabilityFinding]:
        findings = []
        try:
            cors_headers = {"Origin": "https://untrusted-external-domain.example"}
            cors_resp = self.session.options(target_url, headers=cors_headers, timeout=self.timeout, verify=False)
            allow_origin = cors_resp.headers.get("access-control-allow-origin", "").strip()
            allow_creds = cors_resp.headers.get("access-control-allow-credentials", "").lower() == "true"

            if allow_origin == "*":
                findings.append(VulnerabilityFinding(
                    id="CORS-WILDCARD-ORIGIN",
                    title="Permissive Wildcard CORS Configuration (Access-Control-Allow-Origin: *)",
                    severity=SeverityLevel.MEDIUM,
                    category="CORS Misconfiguration",
                    description="The server returns 'Access-Control-Allow-Origin: *', allowing any arbitrary domain to access API endpoints.",
                    evidence=f"Access-Control-Allow-Origin: *",
                    url=target_url,
                    cwe="CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
                    remediation="Restrict Access-Control-Allow-Origin to trusted origins explicitly instead of wildcards.",
                    cvss_score=5.3
                ))
            elif allow_origin == "https://untrusted-external-domain.example" and allow_creds:
                findings.append(VulnerabilityFinding(
                    id="CORS-ARBITRARY-ORIGIN-CREDENTIALS",
                    title="Dangerous CORS Reflection with Credentials Allowed",
                    severity=SeverityLevel.HIGH,
                    category="CORS Misconfiguration",
                    description="Server reflects arbitrary origin headers while enabling Access-Control-Allow-Credentials: true, allowing external sites to read authenticated user responses.",
                    evidence=f"Origin reflected: {allow_origin}, Credentials: true",
                    url=target_url,
                    cwe="CWE-942",
                    remediation="Validate Origin against a strict whitelist before echoing it back and never pair reflected origins with credentials.",
                    cvss_score=8.1
                ))
        except Exception:
            pass
        return findings

    def _audit_sensitive_paths(self, base_url: str) -> List[VulnerabilityFinding]:
        findings = []
        parsed = urllib.parse.urlparse(base_url)
        root_url = f"{parsed.scheme}://{parsed.netloc}"

        probe_targets = [
            ("/.env", "Environment configuration file containing database credentials and secrets", SeverityLevel.CRITICAL, 9.8),
            ("/.git/HEAD", "Exposed Git repository metadata enabling source code reconstruction", SeverityLevel.HIGH, 8.5),
            ("/wp-config.php.bak", "WordPress backup configuration file disclosing database passwords", SeverityLevel.HIGH, 8.2),
            ("/robots.txt", "Robots.txt file which may disclose sensitive hidden admin paths", SeverityLevel.INFO, 0.0),
        ]

        for path, desc, severity, cvss in probe_targets:
            test_url = root_url + path
            try:
                r = self.session.get(test_url, timeout=self.timeout, allow_redirects=False, verify=False)
                # Check status and content verification to avoid false positives (e.g. 200 custom 404 pages)
                if r.status_code == 200:
                    is_real_leak = False
                    if path == "/.env" and ("=" in r.text or "KEY" in r.text or "DB_" in r.text):
                        is_real_leak = True
                    elif path == "/.git/HEAD" and "ref: refs/" in r.text:
                        is_real_leak = True
                    elif path == "/robots.txt" and "Disallow:" in r.text:
                        is_real_leak = True
                    elif path.endswith(".bak") and len(r.text) > 20:
                        is_real_leak = True

                    if is_real_leak:
                        findings.append(VulnerabilityFinding(
                            id=f"LEAK-EXPOSED-{path.replace('/', '_').replace('.', '')}",
                            title=f"Publicly Accessible Sensitive File: {path}",
                            severity=severity,
                            category="Information Disclosure & File Exposure",
                            description=f"Accessible endpoint found at {path}. {desc}.",
                            evidence=f"HTTP 200 OK at {test_url}. Sample snippet: {r.text[:120].strip()}",
                            url=test_url,
                            cwe="CWE-552: Files or Directories Accessible to External Parties",
                            remediation=f"Block public access to {path} in web server rules (e.g. location ~ /\\. {{ deny all; }}).",
                            cvss_score=cvss
                        ))
            except Exception:
                pass

        return findings

