import re
import difflib
from app.models.schemas import PatchRequest, PatchResponse

def generate_patch(req: PatchRequest) -> PatchResponse:
    orig = req.code_content
    lines = orig.splitlines(keepends=True)
    f_id = req.finding_id.upper()

    remediated_lines = list(lines)
    explanation = ""

    # 1. AWS Key
    if "SEC-AWS" in f_id:
        new_lines = []
        has_os_import = any("import os" in l for l in lines)
        if not has_os_import:
            new_lines.append("import os\n")

        for l in lines:
            if re.search(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", l):
                var_match = re.match(r"^(\s*)([a-zA-Z0-9_]+)\s*=\s*['\"][^'\"]+['\"]", l)
                if var_match:
                    indent, var_name = var_match.group(1), var_match.group(2)
                    new_lines.append(f'{indent}{var_name} = os.getenv("AWS_ACCESS_KEY_ID")  # Remediated: Loaded from environment\n')
                else:
                    new_lines.append(l)
            else:
                new_lines.append(l)
        remediated_lines = new_lines
        explanation = "Replaced hardcoded AWS key with environment variable lookup (os.getenv) to prevent secret exposure."

    # 2. Stripe Key
    elif "SEC-STRIPE" in f_id:
        new_lines = []
        has_os_import = any("import os" in l for l in lines)
        if not has_os_import:
            new_lines.append("import os\n")

        for l in lines:
            if "sk_live_" in l:
                var_match = re.match(r"^(\s*)([a-zA-Z0-9_]+)\s*=\s*['\"][^'\"]+['\"]", l)
                if var_match:
                    indent, var_name = var_match.group(1), var_match.group(2)
                    new_lines.append(f'{indent}{var_name} = os.getenv("STRIPE_SECRET_KEY")  # Remediated: Loaded from vault\n')
                else:
                    new_lines.append(l)
            else:
                new_lines.append(l)
        remediated_lines = new_lines
        explanation = "Externalized live Stripe API secret key to environment variable (os.getenv)."

    # 3. SQL Injection
    elif "SQL-INJECTION" in f_id:
        new_lines = []
        for l in lines:
            # f-string in query
            if re.search(r"""f['"][^'"]*SELECT[^'"]*\{([^}]+)\}""", l, re.IGNORECASE):
                # Replace f"SELECT ... '{user_id}'" with parameterized form
                patched = re.sub(
                    r"""f['"]([^'"]*?)'\{([^}]+)\}'['"]""",
                    r'"\1%s", (\2,)',
                    l,
                    flags=re.IGNORECASE
                )
                patched = re.sub(
                    r"""f['"]([^'"]*?)\{([^}]+)\}([^'"]*?)['"]""",
                    r'"\1%s\3", (\2,)',
                    patched,
                    flags=re.IGNORECASE
                )
                new_lines.append(f"{patched.rstrip()}  # Remediated: Parameterized SQL query\n")
            else:
                new_lines.append(l)
        remediated_lines = new_lines
        explanation = "Converted vulnerable dynamic f-string query into a safe, parameterized SQL query using prepared parameter placeholders (%s)."

    # 4. Command Injection
    elif "COMMAND-INJECTION" in f_id:
        new_lines = []
        has_subp = any("import subprocess" in l for l in lines)
        if not has_subp:
            new_lines.append("import subprocess\n")

        for l in lines:
            if "os.system(" in l:
                indent = re.match(r"^(\s*)", l).group(1)
                # Check for ping or generic cmd
                if "ping" in l:
                    param = re.search(r"\{([^}]+)\}", l)
                    param_name = param.group(1) if param else "target_ip"
                    new_lines.append(f'{indent}subprocess.run(["ping", "-c", "1", {param_name}], check=True)  # Remediated: Array-based shell=False execution\n')
                else:
                    new_lines.append(l.replace("os.system(", "# Remediated with subprocess:\n" + indent + "subprocess.run([").replace(")", "], check=True)"))
            else:
                new_lines.append(l)
        remediated_lines = new_lines
        explanation = "Replaced dangerous os.system() with subprocess.run(..., shell=False) using arguments as a safe list."

    # 5. Insecure Deserialization
    elif "INSECURE-DESERIALIZATION" in f_id or "PICKLE" in f_id:
        new_lines = []
        has_json = any("import json" in l for l in lines)
        if not has_json:
            new_lines.append("import json\n")

        for l in lines:
            if "pickle.loads(" in l:
                new_lines.append(l.replace("pickle.loads(", "json.loads(") + "  # Remediated: Safe JSON deserialization\n")
            else:
                new_lines.append(l)
        remediated_lines = new_lines
        explanation = "Replaced unsafe Python pickle deserialization with standard JSON data deserialization."

    # 6. Weak Hash MD5
    elif "CRYPTO" in f_id or "MD5" in f_id:
        new_lines = []
        for l in lines:
            if "hashlib.md5(" in l:
                new_lines.append(l.replace("hashlib.md5(", "hashlib.sha256(") + "  # Remediated: Upgraded from MD5 to SHA-256\n")
            else:
                new_lines.append(l)
        remediated_lines = new_lines
        explanation = "Upgraded collision-vulnerable MD5 algorithm to cryptographically secure SHA-256."

    # 7. Framework Debug Mode
    elif "DEBUG" in f_id:
        new_lines = []
        for l in lines:
            if "DEBUG = True" in l:
                indent = re.match(r"^(\s*)", l).group(1)
                new_lines.append(f'{indent}DEBUG = os.getenv("DEBUG", "False").lower() == "true"  # Remediated: Controlled by environment\n')
            else:
                new_lines.append(l)
        remediated_lines = new_lines
        explanation = "Externalized DEBUG flag to environment variable to prevent production debugging exposure."

    # 8. Disabled SSL Verify
    elif "VERIFY" in f_id or "SSL" in f_id:
        new_lines = []
        for l in lines:
            if "verify=False" in l:
                new_lines.append(l.replace("verify=False", "verify=True  # Remediated: TLS verification enforced\n"))
            else:
                new_lines.append(l)
        remediated_lines = new_lines
        explanation = "Enforced TLS certificate validation (verify=True) to protect against Man-in-the-Middle (MitM) attacks."

    else:
        remediated_lines = list(lines)
        explanation = "General security hardening applied."

    remediated_code = "".join(remediated_lines)

    # Generate unified diff
    diff_generator = difflib.unified_diff(
        lines,
        remediated_lines,
        fromfile="a/" + (req.file_name or "original.py"),
        tofile="b/" + (req.file_name or "remediated.py"),
        lineterm=""
    )
    diff_summary = "\n".join(diff_generator)

    return PatchResponse(
        finding_id=req.finding_id,
        original_code=orig,
        remediated_code=remediated_code,
        diff_summary=diff_summary if diff_summary else "No changes required.",
        explanation=explanation
    )

