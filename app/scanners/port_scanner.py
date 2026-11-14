import socket
import concurrent.futures
from typing import List, Dict, Tuple, Any
from app.models.schemas import VulnerabilityFinding, SeverityLevel

PORT_DATABASE: Dict[int, Dict[str, Any]] = {
    21: {
        "service": "FTP",
        "severity": SeverityLevel.HIGH,
        "title": "Unencrypted FTP Port 21 Open to Network",
        "description": "Port 21 (File Transfer Protocol) transfers credentials and files in plaintext without encryption, exposing session tokens to sniffing.",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "remediation": "Migrate to SFTP (SSH File Transfer Protocol) over port 22 or FTPS (FTP over TLS).",
        "cvss": 7.5
    },
    22: {
        "service": "SSH",
        "severity": SeverityLevel.INFO,
        "title": "SSH Service Detected on Port 22",
        "description": "Secure Shell (SSH) is accessible. Ensure password authentication is disabled and public-key authentication is enforced.",
        "cwe": "CWE-287: Improper Authentication",
        "remediation": "Enforce ed25519 or RSA-4096 SSH keys, disable root login (PermitRootLogin no), and use fail2ban to mitigate brute force.",
        "cvss": 0.0
    },
    23: {
        "service": "Telnet",
        "severity": SeverityLevel.CRITICAL,
        "title": "Obsolete Insecure Telnet Port 23 Open",
        "description": "Telnet communicates in completely unencrypted cleartext. All commands, usernames, and passwords can be captured via network interception.",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "remediation": "Immediately terminate Telnet service and replace with SSH.",
        "cvss": 9.0
    },
    25: {
        "service": "SMTP",
        "severity": SeverityLevel.MEDIUM,
        "title": "Mail Transfer (SMTP) Port 25 Accessible",
        "description": "Port 25 (SMTP) is open. Ensure the server is not configured as an open relay and supports STARTTLS.",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "remediation": "Enforce SMTP authentication, enforce STARTTLS encryption, and prevent open mail relays.",
        "cvss": 5.3
    },
    53: {
        "service": "DNS",
        "severity": SeverityLevel.INFO,
        "title": "DNS Server Port 53 Open",
        "description": "Domain Name System (DNS) service detected. Verify that recursive DNS queries are disabled for external clients to avoid DNS amplification.",
        "cwe": "CWE-406: Insufficient Control of Network Message Volume (Amplification)",
        "remediation": "Restrict DNS recursion to internal trusted subnets only.",
        "cvss": 0.0
    },
    80: {
        "service": "HTTP",
        "severity": SeverityLevel.MEDIUM,
        "title": "Plaintext HTTP Port 80 Open",
        "description": "Port 80 (HTTP) is open. Traffic should automatically redirect to HTTPS (port 443).",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "remediation": "Configure 301 Permanent Redirect to HTTPS for all incoming HTTP requests.",
        "cvss": 4.8
    },
    110: {
        "service": "POP3",
        "severity": SeverityLevel.HIGH,
        "title": "Unencrypted POP3 Mail Port 110 Open",
        "description": "POP3 email retrieval operates over cleartext.",
        "cwe": "CWE-319",
        "remediation": "Enforce POP3S (Port 995) with TLS.",
        "cvss": 7.4
    },
    143: {
        "service": "IMAP",
        "severity": SeverityLevel.HIGH,
        "title": "Unencrypted IMAP Mail Port 143 Open",
        "description": "IMAP email retrieval operates over cleartext.",
        "cwe": "CWE-319",
        "remediation": "Enforce IMAPS (Port 993) with TLS encryption.",
        "cvss": 7.4
    },
    443: {
        "service": "HTTPS",
        "severity": SeverityLevel.INFO,
        "title": "HTTPS Secure Web Port 443 Open",
        "description": "Secure encrypted web service detected.",
        "cwe": "CWE-699",
        "remediation": "Maintain updated TLS certificate and keep modern ciphers enabled.",
        "cvss": 0.0
    },
    3306: {
        "service": "MySQL Database",
        "severity": SeverityLevel.HIGH,
        "title": "MySQL Database Port 3306 Exposed to Network",
        "description": "Port 3306 is open. Direct external exposure of database services invites brute-force attacks and potential exploitation of database vulnerabilities.",
        "cwe": "CWE-284: Improper Access Control",
        "remediation": "Bind MySQL to localhost (127.0.0.1) or restrict access via firewall rules (UFW/Security Groups) or a secure VPN.",
        "cvss": 8.1
    },
    3389: {
        "service": "RDP",
        "severity": SeverityLevel.HIGH,
        "title": "Remote Desktop Protocol (RDP) Port 3389 Exposed",
        "description": "Exposing Windows RDP directly to public or untrusted networks poses critical risks of credential brute-forcing and ransomware deployment.",
        "cwe": "CWE-284: Improper Access Control",
        "remediation": "Place RDP behind an encrypted VPN, enable Network Level Authentication (NLA), or use a zero-trust bastion.",
        "cvss": 8.6
    },
    5432: {
        "service": "PostgreSQL Database",
        "severity": SeverityLevel.HIGH,
        "title": "PostgreSQL Database Port 5432 Exposed to Network",
        "description": "PostgreSQL database port is open to external network access.",
        "cwe": "CWE-284: Improper Access Control",
        "remediation": "Bind listen_addresses to localhost or internal private IP, and configure pg_hba.conf strictly.",
        "cvss": 8.1
    },
    6379: {
        "service": "Redis In-Memory Store",
        "severity": SeverityLevel.CRITICAL,
        "title": "Exposed Redis Cache/Database Port 6379",
        "description": "Redis is designed for trusted internal environments. An exposed Redis instance often lacks authentication, allowing unauthorized data dump or remote code execution via cron/ssh key writes.",
        "cwe": "CWE-306: Missing Authentication for Critical Function",
        "remediation": "Bind Redis to 127.0.0.1, set a strong requirepass password, and enable protected-mode.",
        "cvss": 9.4
    },
    8080: {
        "service": "HTTP Alternate / Proxy",
        "severity": SeverityLevel.LOW,
        "title": "Alternative HTTP Port 8080 Open",
        "description": "Commonly used for development or proxy servers. Ensure administrative panels or debug consoles are not exposed unauthenticated.",
        "cwe": "CWE-200",
        "remediation": "Verify that sensitive admin endpoints on 8080 require authentication.",
        "cvss": 3.5
    },
    9200: {
        "service": "Elasticsearch",
        "severity": SeverityLevel.HIGH,
        "title": "Elasticsearch Port 9200 Exposed",
        "description": "Elasticsearch port 9200 is open. Unauthenticated Elasticsearch instances frequently suffer complete data exfiltration or deletion.",
        "cwe": "CWE-306: Missing Authentication for Critical Function",
        "remediation": "Enable Elastic Security (X-Pack), configure TLS, and restrict access to private internal subnets.",
        "cvss": 8.5
    },
    27017: {
        "service": "MongoDB",
        "severity": SeverityLevel.CRITICAL,
        "title": "Exposed MongoDB Database Port 27017",
        "description": "MongoDB port 27017 is open to network. Without strict authentication, attackers can query or drop all databases.",
        "cwe": "CWE-306: Missing Authentication for Critical Function",
        "remediation": "Enable authentication (auth = true / authorization: enabled) and bind to 127.0.0.1.",
        "cvss": 9.4
    }
}

class PortSecurityAuditor:
    def __init__(self, timeout: float = 0.6):
        self.timeout = timeout

    def check_port(self, host: str, port: int) -> Tuple[int, bool]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            result = s.connect_ex((host, port))
            s.close()
            return port, result == 0
        except Exception:
            return port, False

    def scan(self, target_host: str, port_selection: str = "common") -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []

        # Sanitize host: remove http:// or trailing slashes if present
        host = target_host.strip().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            return [VulnerabilityFinding(
                id="PORT-DNS-ERROR",
                title="Host Resolution Failed",
                severity=SeverityLevel.INFO,
                category="Network / DNS",
                description=f"Could not resolve host '{host}': {str(e)}",
                evidence=str(e),
                remediation="Ensure the hostname or IP address is valid and reachable.",
                cvss_score=0.0
            )]

        # Determine target ports
        if port_selection == "web":
            ports = [80, 443, 8080, 8443, 8000, 3000, 5000]
        elif port_selection == "database":
            ports = [3306, 5432, 6379, 9200, 27017, 1433, 1521]
        else: # "common"
            ports = sorted(list(PORT_DATABASE.keys()) + [8000, 8443, 8888, 9000, 3000, 5000])

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.check_port, ip, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                p, is_open = future.result()
                if is_open:
                    open_ports.append(p)

        open_ports.sort()

        for port in open_ports:
            if port in PORT_DATABASE:
                info = PORT_DATABASE[port]
                findings.append(VulnerabilityFinding(
                    id=f"PORT-OPEN-{port}",
                    title=info["title"],
                    severity=info["severity"],
                    category="Network & Port Exposure",
                    description=f"{info['description']} (Host: {host} [{ip}], Port: {port}/{info['service']})",
                    evidence=f"TCP Port {port} is OPEN and accepting connections on {ip}.",
                    cwe=info["cwe"],
                    remediation=info["remediation"],
                    cvss_score=info["cvss"]
                ))
            else:
                findings.append(VulnerabilityFinding(
                    id=f"PORT-OPEN-{port}",
                    title=f"Open Port Detected: {port}/TCP",
                    severity=SeverityLevel.LOW,
                    category="Network & Port Exposure",
                    description=f"Port {port} is open on target host ({host} [{ip}]). Verify if this service needs to be accessible.",
                    evidence=f"TCP Port {port} is OPEN.",
                    cwe="CWE-284: Improper Access Control",
                    remediation=f"If port {port} is not required externally, close it using host firewalls (e.g. ufw or Windows Firewall).",
                    cvss_score=3.0
                ))

        if not open_ports:
            findings.append(VulnerabilityFinding(
                id="PORT-ALL-FILTERED",
                title="No Open Scanned Ports Discovered",
                severity=SeverityLevel.INFO,
                category="Network / Firewall",
                description=f"All scanned common ports on {host} ({ip}) were filtered or closed. Firewall rules are effectively blocking unsolicited probes.",
                evidence="0 open ports detected among scanned range.",
                remediation="Continue maintaining strict ingress firewall policies.",
                cvss_score=0.0
            ))

        return findings
