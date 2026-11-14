import re
import json
from typing import List, Dict, Any, Optional
from packaging import version
from app.models.schemas import VulnerabilityFinding, SeverityLevel

KNOWN_VULNERABLE_PACKAGES: List[Dict[str, Any]] = [
    {
        "ecosystem": "python",
        "package": "requests",
        "vulnerable_below": "2.31.0",
        "fixed_version": "2.31.0",
        "cve": "CVE-2023-32681",
        "severity": SeverityLevel.HIGH,
        "title": "Requests: Sensitive Header Leak on Cross-Origin Redirect",
        "description": "Requests prior to 2.31.0 leak Authorization headers during cross-origin HTTPS to HTTP redirects.",
        "cvss": 7.5,
        "remediation": "Upgrade requests to >= 2.31.0: pip install --upgrade requests"
    },
    {
        "ecosystem": "python",
        "package": "urllib3",
        "vulnerable_below": "2.0.7",
        "fixed_version": "2.0.7",
        "cve": "CVE-2023-45803",
        "severity": SeverityLevel.HIGH,
        "title": "urllib3: Request Body Stripping Failure on Redirect",
        "description": "urllib3 fails to strip HTTP request bodies on certain redirect codes, resulting in sensitive data exposure.",
        "cvss": 7.5,
        "remediation": "Upgrade urllib3 to >= 2.0.7: pip install --upgrade urllib3"
    },
    {
        "ecosystem": "python",
        "package": "django",
        "vulnerable_below": "5.0.2",
        "fixed_version": "5.0.2",
        "cve": "CVE-2024-24680",
        "severity": SeverityLevel.CRITICAL,
        "title": "Django: Potential Denial of Service in intcomma Filter",
        "description": "In Django before 5.0.2, the intcomma template filter is subject to quadratic string concatenation leading to denial of service.",
        "cvss": 7.5,
        "remediation": "Upgrade Django to >= 5.0.2: pip install --upgrade django"
    },
    {
        "ecosystem": "python",
        "package": "flask",
        "vulnerable_below": "2.2.5",
        "fixed_version": "2.2.5",
        "cve": "CVE-2023-30861",
        "severity": SeverityLevel.HIGH,
        "title": "Flask: Session Cookie Invalidation Vulnerability",
        "description": "Under specific conditions, session cookies may not be properly cleared or validated across differing origins.",
        "cvss": 7.5,
        "remediation": "Upgrade Flask to >= 2.2.5: pip install --upgrade flask"
    },
    {
        "ecosystem": "python",
        "package": "pyyaml",
        "vulnerable_below": "5.4.1",
        "fixed_version": "5.4.1",
        "cve": "CVE-2020-14343",
        "severity": SeverityLevel.CRITICAL,
        "title": "PyYAML: Arbitrary Code Execution via FullLoader",
        "description": "PyYAML before 5.4.1 can allow arbitrary code execution when untrusted input is processed with FullLoader.",
        "cvss": 9.8,
        "remediation": "Upgrade PyYAML to >= 5.4.1 and always utilize yaml.safe_load(): pip install --upgrade pyyaml"
    },
    {
        "ecosystem": "python",
        "package": "cryptography",
        "vulnerable_below": "42.0.4",
        "fixed_version": "42.0.4",
        "cve": "CVE-2024-26130",
        "severity": SeverityLevel.HIGH,
        "title": "Cryptography: NULL Pointer Dereference in PKCS7 Parsing",
        "description": "Vulnerability in cryptography before 42.0.4 where parsing PKCS#7 structures could cause segmentation fault / DoS.",
        "cvss": 7.5,
        "remediation": "Upgrade cryptography to >= 42.0.4: pip install --upgrade cryptography"
    },
    {
        "ecosystem": "python",
        "package": "pillow",
        "vulnerable_below": "10.2.0",
        "fixed_version": "10.2.0",
        "cve": "CVE-2024-28219",
        "severity": SeverityLevel.CRITICAL,
        "title": "Pillow: Buffer Overflow in ImagingSdsRead",
        "description": "Buffer overflow in Pillow before 10.2.0 allows attackers to cause arbitrary code execution or crash via malformed image files.",
        "cvss": 9.8,
        "remediation": "Upgrade pillow to >= 10.2.0: pip install --upgrade pillow"
    },
    {
        "ecosystem": "python",
        "package": "werkzeug",
        "vulnerable_below": "3.0.3",
        "fixed_version": "3.0.3",
        "cve": "CVE-2024-34069",
        "severity": SeverityLevel.HIGH,
        "title": "Werkzeug: Debugger Console Execution Flaw",
        "description": "Security flaw in Werkzeug's interactive debugger debugger PIN validation.",
        "cvss": 7.5,
        "remediation": "Upgrade werkzeug to >= 3.0.3: pip install --upgrade werkzeug"
    },
    {
        "ecosystem": "nodejs",
        "package": "lodash",
        "vulnerable_below": "4.17.21",
        "fixed_version": "4.17.21",
        "cve": "CVE-2020-8203",
        "severity": SeverityLevel.CRITICAL,
        "title": "Lodash: Prototype Pollution Vulnerability",
        "description": "Prototype pollution in lodash via zipObjectDeep function allows modification of Object prototype.",
        "cvss": 9.8,
        "remediation": "Update lodash in package.json to >= 4.17.21 (npm update lodash)."
    },
    {
        "ecosystem": "nodejs",
        "package": "axios",
        "vulnerable_below": "1.6.0",
        "fixed_version": "1.6.0",
        "cve": "CVE-2023-45857",
        "severity": SeverityLevel.HIGH,
        "title": "Axios: Cross-Site Request Forgery / SSRF in redirects",
        "description": "Axios before 1.6.0 leaks XSRF-TOKEN in certain redirect conditions.",
        "cvss": 7.5,
        "remediation": "Update axios to >= 1.6.0 (npm update axios)."
    },
    {
        "ecosystem": "nodejs",
        "package": "express",
        "vulnerable_below": "4.19.2",
        "fixed_version": "4.19.2",
        "cve": "CVE-2024-29041",
        "severity": SeverityLevel.MEDIUM,
        "title": "Express: Open Redirect via Malformed URLs",
        "description": "Express before 4.19.2 handles malformed URLs inappropriately, facilitating Open Redirect vulnerabilities.",
        "cvss": 6.1,
        "remediation": "Update express to >= 4.19.2: npm update express"
    }
]

class DependencyScanner:
    def __init__(self):
        self.db = KNOWN_VULNERABLE_PACKAGES

    def scan_requirements_txt(self, content: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Parse lines like: requests==2.28.1, urllib3~=1.26.5, django>=3.2,<4.0
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[=><~]+)?([0-9a-zA-Z\.\-]+)?", line)
            if match:
                pkg_name = match.group(1).lower().replace("_", "-")
                pkg_ver_str = match.group(2)

                if pkg_ver_str:
                    try:
                        installed_v = version.parse(pkg_ver_str)
                    except Exception:
                        continue

                    for advisory in self.db:
                        if advisory["ecosystem"] == "python" and advisory["package"].lower().replace("_", "-") == pkg_name:
                            vuln_below = version.parse(advisory["vulnerable_below"])
                            if installed_v < vuln_below:
                                findings.append(VulnerabilityFinding(
                                    id=f"SCA-{advisory['cve']}-{pkg_name}",
                                    title=f"{advisory['title']} ({pkg_name} {pkg_ver_str})",
                                    severity=advisory["severity"],
                                    category="Vulnerable Dependency (SCA)",
                                    description=f"{advisory['description']} Detected version: {pkg_ver_str}. Safe version: >= {advisory['fixed_version']}.",
                                    evidence=f"requirements.txt line {line_idx}: {line}",
                                    cwe=f"{advisory['cve']}",
                                    remediation=advisory["remediation"],
                                    cvss_score=advisory["cvss"]
                                ))

        return findings

    def scan_package_json(self, content: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            data = json.loads(content)
        except Exception as e:
            return [VulnerabilityFinding(
                id="SCA-JSON-PARSE-ERROR",
                title="Invalid package.json File",
                severity=SeverityLevel.INFO,
                category="Configuration",
                description=f"Could not parse package.json: {str(e)}",
                evidence=str(e),
                remediation="Ensure valid JSON syntax.",
                cvss_score=0.0
            )]

        deps = {}
        if "dependencies" in data and isinstance(data["dependencies"], dict):
            deps.update(data["dependencies"])
        if "devDependencies" in data and isinstance(data["devDependencies"], dict):
            deps.update(data["devDependencies"])

        for pkg, ver_spec in deps.items():
            pkg_name = pkg.lower()
            # Clean version string (e.g., ^4.17.15 -> 4.17.15)
            ver_clean = re.sub(r"[^0-9\.]", "", ver_spec)
            if not ver_clean:
                continue

            try:
                installed_v = version.parse(ver_clean)
            except Exception:
                continue

            for advisory in self.db:
                if advisory["ecosystem"] == "nodejs" and advisory["package"].lower() == pkg_name:
                    vuln_below = version.parse(advisory["vulnerable_below"])
                    if installed_v < vuln_below:
                        findings.append(VulnerabilityFinding(
                            id=f"SCA-{advisory['cve']}-{pkg_name}",
                            title=f"{advisory['title']} ({pkg_name} {ver_spec})",
                            severity=advisory["severity"],
                            category="Vulnerable Dependency (SCA)",
                            description=f"{advisory['description']} Specified: {ver_spec}. Safe version: >= {advisory['fixed_version']}.",
                            evidence=f"package.json dependency: \"{pkg}\": \"{ver_spec}\"",
                            cwe=f"{advisory['cve']}",
                            remediation=advisory["remediation"],
                            cvss_score=advisory["cvss"]
                        ))

        return findings

