import os
import json
from typing import List, Optional, Dict, Any
from app.models.schemas import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    ScanResult,
    VulnerabilityFinding
)
from app.ai.knowledge_base import SECURITY_KNOWLEDGE_BASE

SYSTEM_PROMPT = """You are SentinelAI, an elite Defensive Security Engineering AI Agent.
Your mission is to help developers, security engineers, and DevOps teams audit, explain, and fix security vulnerabilities.

Guidelines:
1. Always maintain a defensive posture. Explain the underlying risk, root cause, and standard CVSS impact.
2. Provide concrete, production-ready remediation code and configuration fixes.
3. Reference relevant OWASP Top 10 categories, CWE numbers, and industry best practices.
4. Structure your answers with clear headings, bullet points, and code blocks with syntax highlighting.
5. If referring to a specific scan finding, highlight the affected line or header and provide a side-by-side Before/After fix.
"""

class SecurityAIAgent:
    def __init__(self):
        self.system_prompt = SYSTEM_PROMPT

    def respond(self, request: ChatRequest, active_scan: Optional[ScanResult] = None) -> ChatResponse:
        provider = (request.provider or "offline").lower()
        api_key = request.api_key or os.getenv("AI_API_KEY") or os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("GROQ_API_KEY")

        # Context build
        context_str = self._build_context(active_scan)

        # Dispatch based on provider
        if provider == "gemini" and api_key:
            return self._call_gemini(request.message, request.conversation_history, context_str, api_key)
        elif provider == "openai" and api_key:
            return self._call_openai(request.message, request.conversation_history, context_str, api_key)
        elif provider == "groq" and api_key:
            return self._call_groq(request.message, request.conversation_history, context_str, api_key)
        else:
            # Default to Offline Security Expert
            return self._offline_security_expert(request.message, request.conversation_history, context_str, active_scan)

    def _build_context(self, scan: Optional[ScanResult]) -> str:
        if not scan:
            return "No active vulnerability scan context provided."

        ctx = [
            f"Active Scan ID: {scan.scan_id}",
            f"Target: {scan.target} (Type: {scan.scan_type})",
            f"Total Findings: {scan.summary.total_findings} (Critical: {scan.summary.critical_count}, High: {scan.summary.high_count}, Medium: {scan.summary.medium_count}, Low: {scan.summary.low_count})",
            "Findings Overview:"
        ]

        for idx, f in enumerate(scan.findings[:10], start=1):
            ctx.append(f"{idx}. [{f.severity}] {f.title} ({f.category}) - CWE: {f.cwe or 'N/A'}")
            if f.evidence:
                ctx.append(f"   Evidence: {f.evidence}")
            if f.remediation:
                ctx.append(f"   Remediation Note: {f.remediation}")

        return "\n".join(ctx)

    def _offline_security_expert(self, message: str, history: Optional[List[ChatMessage]],
                                 context_str: str, scan: Optional[ScanResult]) -> ChatResponse:
        query_lower = message.lower()
        suggested_actions = [
            "How do I fix the highest severity vulnerability?",
            "Show me secure Nginx / FastAPI security headers",
            "How do I prevent SQL injection with prepared statements?",
            "What is the best way to handle secrets and API keys safely?"
        ]
        references = ["OWASP Top 10:2021", "NIST SP 800-53", "CWE Guidelines"]

        # 1. Target specific findings in active scan
        matched_finding: Optional[VulnerabilityFinding] = None
        if scan and scan.findings:
            for f in scan.findings:
                if f.id.lower() in query_lower or any(word in query_lower for word in f.title.lower().split() if len(word) > 4):
                    matched_finding = f
                    break

        # Check if user asked to fix all or summary of scan
        if any(term in query_lower for term in ["fix all", "summary", "overview", "what are the vulnerabilities", "report"]):
            if scan and scan.findings:
                reply = f"### 🛡️ Vulnerability Audit Summary for `{scan.target}`\n\n"
                reply += f"- **Risk Level Score**: `{scan.summary.risk_score}/100`\n"
                reply += f"- **Findings Found**: {scan.summary.total_findings} (🔴 {scan.summary.critical_count} Critical, 🟠 {scan.summary.high_count} High, 🟡 {scan.summary.medium_count} Medium, 🟢 {scan.summary.low_count} Low)\n\n"
                reply += "#### Priority Remediation Plan:\n\n"
                for idx, f in enumerate(scan.findings, start=1):
                    reply += f"{idx}. **[{f.severity}] {f.title}**\n"
                    reply += f"   - **Category**: {f.category} | **CWE**: {f.cwe or 'N/A'}\n"
                    reply += f"   - **Recommended Fix**: {f.remediation}\n\n"
                reply += "\n> 💡 **Next Steps**: Select any individual finding above and ask *'How do I fix [Vulnerability Name]?'* for tailored code implementations."
                return ChatResponse(reply=reply, suggested_actions=suggested_actions, references=references)

        # If matched a specific finding
        if matched_finding:
            reply = f"### 🔍 Detailed Analysis & Remediation: **{matched_finding.title}**\n\n"
            reply += f"- **Severity**: `{matched_finding.severity}` (Estimated CVSS: `{matched_finding.cvss_score}`)\n"
            reply += f"- **Classification**: `{matched_finding.category}` ({matched_finding.cwe or 'CWE'})\n"
            if matched_finding.file_path:
                reply += f"- **File / Line**: `{matched_finding.file_path}` (Line {matched_finding.line_number or 'N/A'})\n"
            if matched_finding.evidence:
                reply += f"\n**Detection Evidence:**\n```text\n{matched_finding.evidence}\n```\n"

            reply += f"\n#### 🚨 Root Cause & Impact:\n{matched_finding.description}\n"
            reply += f"\n#### 🛠️ Step-by-Step Defensive Remediation:\n1. **Immediate Action**: {matched_finding.remediation}\n"
            reply += "2. **Architecture Defense**: Apply defense-in-depth principles: validate all inputs, enforce principle of least privilege, and enable automated CI/CD linting.\n"
            reply += "3. **Verification**: Re-run the VulnGuard scan after applying your patch to confirm the finding is resolved.\n"

            return ChatResponse(
                reply=reply,
                suggested_actions=[
                    f"Show code fix for {matched_finding.title}",
                    "What is the worst-case exploit scenario?",
                    "How to verify this fix in CI/CD?"
                ],
                references=[matched_finding.cwe or "OWASP Top 10", "CWE Security Standard"]
            )

        # 2. Match Knowledge Base topics
        if any(w in query_lower for w in ["sql", "sqli", "injection", "database query"]):
            kb = SECURITY_KNOWLEDGE_BASE["sql_injection"]
            reply = f"### 🛡️ Defensive Guide: {kb['title']}\n\n"
            reply += f"{kb['description']}\n\n"
            reply += f"**Impact**: {kb['risk_impact']}\n\n"
            reply += "#### 🛠️ Remediation Checklist:\n"
            for step in kb["remediation_steps"]:
                reply += f"- {step}\n"
            reply += "\n#### 💻 Code Comparison (Before vs After):\n\n"
            reply += f"❌ **Vulnerable (String Formatting):**\n```python\n{kb['code_example']['vulnerable']}\n```\n\n"
            reply += f"✅ **Remediated (Parameterized Prepared Query):**\n```python\n{kb['code_example']['secure']}\n```\n"
            return ChatResponse(reply=reply, suggested_actions=suggested_actions, references=references)

        if any(w in query_lower for w in ["command", "os.system", "shell", "subprocess", "rce"]):
            kb = SECURITY_KNOWLEDGE_BASE["command_injection"]
            reply = f"### 🛡️ Defensive Guide: {kb['title']}\n\n"
            reply += f"{kb['description']}\n\n"
            reply += f"**Impact**: {kb['risk_impact']}\n\n"
            reply += "#### 🛠️ Remediation Steps:\n"
            for step in kb["remediation_steps"]:
                reply += f"- {step}\n"
            reply += "\n#### 💻 Code Fix:\n\n"
            reply += f"❌ **Vulnerable:**\n```python\n{kb['code_example']['vulnerable']}\n```\n\n"
            reply += f"✅ **Remediated (Safe List Execution):**\n```python\n{kb['code_example']['secure']}\n```\n"
            return ChatResponse(reply=reply, suggested_actions=suggested_actions, references=references)

        if any(w in query_lower for w in ["secret", "key", "token", "password", "credential", "aws", "stripe"]):
            kb = SECURITY_KNOWLEDGE_BASE["hardcoded_secrets"]
            reply = f"### 🛡️ Defensive Guide: {kb['title']}\n\n"
            reply += f"{kb['description']}\n\n"
            reply += f"**Impact**: {kb['risk_impact']}\n\n"
            reply += "#### 🛠️ Remediation Steps:\n"
            for step in kb["remediation_steps"]:
                reply += f"- {step}\n"
            reply += "\n#### 💻 Implementation:\n\n"
            reply += f"❌ **Vulnerable:**\n```python\n{kb['code_example']['vulnerable']}\n```\n\n"
            reply += f"✅ **Remediated (.env / Environment Variables):**\n```python\n{kb['code_example']['secure']}\n```\n"
            return ChatResponse(reply=reply, suggested_actions=suggested_actions, references=references)

        if any(w in query_lower for w in ["header", "csp", "hsts", "x-frame", "clickjacking", "nosniff"]):
            kb = SECURITY_KNOWLEDGE_BASE["security_headers"]
            reply = f"### 🛡️ Defensive Guide: {kb['title']}\n\n"
            reply += f"{kb['description']}\n\n"
            reply += "#### 🛠️ Recommended Header Policy:\n"
            for step in kb["remediation_steps"]:
                reply += f"- `{step}`\n"
            reply += "\n#### 🌐 Configuration Examples:\n\n"
            reply += f"**NGINX Configuration:**\n```nginx\n{kb['code_example']['nginx']}\n```\n\n"
            reply += f"**FastAPI Middleware:**\n```python\n{kb['code_example']['fastapi']}\n```\n"
            return ChatResponse(reply=reply, suggested_actions=suggested_actions, references=references)

        if any(w in query_lower for w in ["port", "redis", "mongo", "mysql", "firewall", "telnet"]):
            kb = SECURITY_KNOWLEDGE_BASE["exposed_ports"]
            reply = f"### 🛡️ Defensive Guide: {kb['title']}\n\n"
            reply += f"{kb['description']}\n\n"
            reply += "#### 🛠️ Remediation Guidelines:\n"
            for step in kb["remediation_steps"]:
                reply += f"- {step}\n"
            reply += "\n#### ⚙️ Configuration Snippets:\n\n"
            reply += f"**Redis Localhost Binding (`redis.conf`):**\n```ini\n{kb['code_example']['redis_conf']}\n```\n\n"
            reply += f"**Host Firewall Rules (UFW):**\n```bash\n{kb['code_example']['ufw_firewall']}\n```\n"
            return ChatResponse(reply=reply, suggested_actions=suggested_actions, references=references)

        # General Security Assistant response
        reply = "### 🛡️ SentinelAI Security Assistant\n\n"
        reply += "I am ready to assist you in hardening your application and remediating vulnerabilities!\n\n"
        if scan and scan.findings:
            reply += f"Currently loaded scan: **{scan.target}** with **{scan.summary.total_findings} findings**.\n\n"
            reply += "You can ask me:\n"
            reply += f"- *'Explain the {scan.findings[0].title} issue and how to resolve it'* \n"
            reply += "- *'Generate a patch for my requirements.txt'* \n"
            reply += "- *'How do I configure Content Security Policy (CSP)?'* \n"
        else:
            reply += "You can run a scan on a Web URL, Code Repository, Open Ports, or Dependency manifest from the Scanner dashboard, or ask me any question regarding secure coding, OWASP Top 10, or cloud security.\n"

        return ChatResponse(reply=reply, suggested_actions=suggested_actions, references=references)

    def _call_gemini(self, message: str, history: Optional[List[ChatMessage]],
                     context_str: str, api_key: str) -> ChatResponse:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            prompt = f"{self.system_prompt}\n\nActive Scan Context:\n{context_str}\n\nUser Question:\n{message}"
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            return ChatResponse(
                reply=response.text or "No response generated.",
                suggested_actions=["Show code implementation", "How to verify in staging?", "Explain underlying CWE"],
                references=["Gemini Security Intelligence", "OWASP Standards"]
            )
        except Exception as e:
            return ChatResponse(
                reply=f"⚠️ Gemini API connection error: {str(e)}. Falling back to offline expert mode.\n\n" +
                      self._offline_security_expert(message, history, context_str, None).reply
            )

    def _call_openai(self, message: str, history: Optional[List[ChatMessage]],
                     context_str: str, api_key: str) -> ChatResponse:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            messages = [{"role": "system", "content": f"{self.system_prompt}\n\nActive Scan Context:\n{context_str}"}]
            if history:
                for h in history[-5:]:
                    messages.append({"role": h.role, "content": h.content})
            messages.append({"role": "user", "content": message})

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=messages
            )
            reply = response.choices[0].message.content or ""
            return ChatResponse(
                reply=reply,
                suggested_actions=["Provide unit test to catch regression", "Review mitigation checklist"],
                references=["OpenAI Model", "CWE / OWASP Framework"]
            )
        except Exception as e:
            return ChatResponse(
                reply=f"⚠️ OpenAI API error: {str(e)}. Falling back to offline expert mode.\n\n" +
                      self._offline_security_expert(message, history, context_str, None).reply
            )

    def _call_groq(self, message: str, history: Optional[List[ChatMessage]],
                   context_str: str, api_key: str) -> ChatResponse:
        try:
            from groq import Groq
            client = Groq(api_key=api_key)
            messages = [{"role": "system", "content": f"{self.system_prompt}\n\nActive Scan Context:\n{context_str}"}]
            if history:
                for h in history[-5:]:
                    messages.append({"role": h.role, "content": h.content})
            messages.append({"role": "user", "content": message})

            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages
            )
            reply = response.choices[0].message.content or ""
            return ChatResponse(
                reply=reply,
                suggested_actions=["Review alternative secure design", "Generate configuration patch"],
                references=["Groq LLaMA-3.3 Engine", "OWASP Top 10"]
            )
        except Exception as e:
            return ChatResponse(
                reply=f"⚠️ Groq API error: {str(e)}. Falling back to offline expert mode.\n\n" +
                      self._offline_security_expert(message, history, context_str, None).reply
            )

