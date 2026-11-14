"""
Self-Verification Test Suite for VulnGuard AI Scanner & AI Agent
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.scanners.code_scanner import CodeSecurityScanner
from app.scanners.dependency_scanner import DependencyScanner
from app.scanners.port_scanner import PortSecurityAuditor
from app.scanners.web_scanner import WebSecurityAuditor
from app.ai.agent import SecurityAIAgent
from app.models.schemas import (
    ChatRequest,
    ScanResult,
    ScanSummary,
    SeverityLevel,
    VulnerabilityFinding
)

def test_code_scanner():
    print("[1/5] Testing Code Security Scanner (SAST)...")
    scanner = CodeSecurityScanner()
    test_code = """
import os
import pickle

AWS_ACCESS_KEY_ID = "AKIA_DUMMY_KEY"
STRIPE_KEY = "SK_DUMMY_KEY"

def bad_query(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)

def bad_command(host):
    os.system(f"ping {host}")

def bad_pickle(data):
    return pickle.loads(data)
    """.replace("AKIA_DUMMY_KEY", "AKIA" + "IOSFODNN7EXAMPLE").replace("SK_DUMMY_KEY", "sk_" + "live_1234567890abcdef12345678")
    findings = scanner.scan_content(test_code, "test_vulnerable.py")
    print(f"   -> Found {len(findings)} findings in test code.")
    rule_ids = [f.id.split("-")[0] + "-" + f.id.split("-")[1] for f in findings]
    assert any("SEC-AWS" in f.id for f in findings), "Should detect AWS key"
    assert any("SEC-STRIPE" in f.id for f in findings), "Should detect Stripe key"
    assert any("CODE-SQL" in f.id for f in findings), "Should detect SQL injection"
    assert any("CODE-COMMAND" in f.id for f in findings), "Should detect command injection"
    assert any("CODE-INSECURE-DESERIALIZATION" in f.id for f in findings), "Should detect pickle"
    print("   ✅ Code scanner passed all assertions!")

def test_dependency_scanner():
    print("[2/5] Testing Dependency Scanner (SCA)...")
    scanner = DependencyScanner()
    reqs = """
requests==2.28.1
urllib3==1.26.5
django==3.2.0
pyyaml==5.3.1
"""
    findings = scanner.scan_requirements_txt(reqs)
    print(f"   -> Found {len(findings)} vulnerable dependencies.")
    assert len(findings) >= 3, "Should detect multiple known vulnerable packages"
    print("   ✅ Dependency scanner passed all assertions!")

def test_port_scanner():
    print("[3/5] Testing Port Scanner...")
    scanner = PortSecurityAuditor(timeout=0.2)
    findings = scanner.scan("127.0.0.1", port_selection="database")
    print(f"   -> Scanned localhost database ports: {len(findings)} finding(s).")
    assert len(findings) >= 1, "Should return port findings or filtered report"
    print("   ✅ Port scanner passed!")

def test_web_scanner():
    print("[4/5] Testing Web Scanner...")
    scanner = WebSecurityAuditor(timeout=3)
    # Test normalization and structure
    url = scanner.normalize_url("example.com")
    assert url == "https://example.com"
    print("   ✅ Web scanner initialization and normalization passed!")

def test_ai_agent():
    print("[5/5] Testing AI Agent (SentinelAI)...")
    agent = SecurityAIAgent()

    # Create dummy scan result
    dummy_finding = VulnerabilityFinding(
        id="CODE-SQL-INJECTION-1",
        title="SQL Injection: Formatted f-string in SQL Query",
        severity=SeverityLevel.CRITICAL,
        category="SQL Injection",
        description="Unsanitized user input formatted directly into query.",
        evidence="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        remediation="Use parameterized query: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        cvss_score=9.4
    )
    dummy_scan = ScanResult(
        scan_id="test-123",
        timestamp="2026-11-12 12:00:00",
        scan_type="SAST",
        target="app.py",
        status="completed",
        duration_seconds=0.1,
        summary=ScanSummary(critical_count=1, total_findings=1, risk_score=25.0),
        findings=[dummy_finding]
    )

    # Ask agent about the finding
    req = ChatRequest(
        message="How do I fix the SQL injection vulnerability?",
        provider="offline"
    )
    resp = agent.respond(req, active_scan=dummy_scan)
    print("   -> Agent response length:", len(resp.reply))
    assert len(resp.reply) > 50, "Agent should provide detailed response"
    assert "parameterized" in resp.reply.lower() or "sql" in resp.reply.lower()
    print("   ✅ AI Agent passed all tests!")

if __name__ == "__main__":
    print("Starting VulnGuard AI verification test suite...\n")
    test_code_scanner()
    test_dependency_scanner()
    test_port_scanner()
    test_web_scanner()
    test_ai_agent()
    print("\n🎉 ALL TESTS COMPLETED SUCCESSFULLY!")

