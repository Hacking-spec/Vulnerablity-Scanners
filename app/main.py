import os
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse

from app.models.schemas import (
    SeverityLevel,
    ScanType,
    VulnerabilityFinding,
    ScanSummary,
    ScanResult,
    WebScanRequest,
    CodeScanRequest,
    PortScanRequest,
    DependencyScanRequest,
    ChatRequest,
    ChatResponse
)
from app.scanners.web_scanner import WebSecurityAuditor
from app.scanners.code_scanner import CodeSecurityScanner
from app.scanners.port_scanner import PortSecurityAuditor
from app.scanners.dependency_scanner import DependencyScanner
from app.ai.agent import SecurityAIAgent

app = FastAPI(
    title="VulnGuard AI - Defensive Vulnerability Scanner & AI Agent",
    description="Multi-engine vulnerability auditor with an integrated conversational AI security assistant.",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan results (persisted for the session)
SCAN_STORE: Dict[str, ScanResult] = {}

# Scanner instances
web_scanner = WebSecurityAuditor()
code_scanner = CodeSecurityScanner()
port_scanner = PortSecurityAuditor()
dep_scanner = DependencyScanner()
ai_agent = SecurityAIAgent()

def calculate_summary(findings: List[VulnerabilityFinding]) -> ScanSummary:
    summary = ScanSummary()
    for f in findings:
        summary.total_findings += 1
        if f.severity == SeverityLevel.CRITICAL:
            summary.critical_count += 1
        elif f.severity == SeverityLevel.HIGH:
            summary.high_count += 1
        elif f.severity == SeverityLevel.MEDIUM:
            summary.medium_count += 1
        elif f.severity == SeverityLevel.LOW:
            summary.low_count += 1
        elif f.severity == SeverityLevel.INFO:
            summary.info_count += 1

    # Risk score calculation
    raw_score = (
        summary.critical_count * 25.0 +
        summary.high_count * 15.0 +
        summary.medium_count * 7.0 +
        summary.low_count * 2.0
    )
    summary.risk_score = round(min(100.0, raw_score), 1)
    return summary

# ----------------- SCAN ENDPOINTS -----------------

@app.post("/api/scan/web", response_model=ScanResult)
async def scan_web(req: WebScanRequest):
    start_time = time.time()
    scan_id = str(uuid.uuid4())[:8]

    findings = web_scanner.scan(
        target_url=req.url,
        check_ssl=req.check_ssl,
        check_headers=req.check_headers,
        check_sensitive_paths=req.check_sensitive_paths,
        check_cors=req.check_cors
    )

    duration = round(time.time() - start_time, 2)
    summary = calculate_summary(findings)

    result = ScanResult(
        scan_id=scan_id,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        scan_type="Web / HTTP Security",
        target=req.url,
        status="completed",
        duration_seconds=duration,
        summary=summary,
        findings=findings
    )
    SCAN_STORE[scan_id] = result
    return result

@app.post("/api/scan/code", response_model=ScanResult)
async def scan_code(req: CodeScanRequest):
    start_time = time.time()
    scan_id = str(uuid.uuid4())[:8]

    findings = []
    target_name = "Code Snippet"

    if req.directory_path:
        target_name = req.directory_path
        findings = code_scanner.scan_directory(req.directory_path)
    elif req.code_content:
        target_name = req.file_name or "snippet.py"
        findings = code_scanner.scan_content(req.code_content, file_name=target_name)
    else:
        raise HTTPException(status_code=400, detail="Provide either code_content or directory_path.")

    duration = round(time.time() - start_time, 2)
    summary = calculate_summary(findings)

    result = ScanResult(
        scan_id=scan_id,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        scan_type="SAST & Secret Detection",
        target=target_name,
        status="completed",
        duration_seconds=duration,
        summary=summary,
        findings=findings
    )
    SCAN_STORE[scan_id] = result
    return result

@app.post("/api/scan/upload-code", response_model=ScanResult)
async def upload_code_file(file: UploadFile = File(...)):
    start_time = time.time()
    scan_id = str(uuid.uuid4())[:8]

    content_bytes = await file.read()
    content_str = content_bytes.decode("utf-8", errors="ignore")

    findings = code_scanner.scan_content(content_str, file_name=file.filename)
    duration = round(time.time() - start_time, 2)
    summary = calculate_summary(findings)

    result = ScanResult(
        scan_id=scan_id,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        scan_type="Uploaded File SAST",
        target=file.filename,
        status="completed",
        duration_seconds=duration,
        summary=summary,
        findings=findings
    )
    SCAN_STORE[scan_id] = result
    return result

@app.post("/api/scan/ports", response_model=ScanResult)
async def scan_ports(req: PortScanRequest):
    start_time = time.time()
    scan_id = str(uuid.uuid4())[:8]

    findings = port_scanner.scan(req.host, port_selection=req.port_range or "common")
    duration = round(time.time() - start_time, 2)
    summary = calculate_summary(findings)

    result = ScanResult(
        scan_id=scan_id,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        scan_type="Network & Port Exposure",
        target=req.host,
        status="completed",
        duration_seconds=duration,
        summary=summary,
        findings=findings
    )
    SCAN_STORE[scan_id] = result
    return result

@app.post("/api/scan/dependencies", response_model=ScanResult)
async def scan_dependencies(req: DependencyScanRequest):
    start_time = time.time()
    scan_id = str(uuid.uuid4())[:8]

    findings = []
    target_name = req.file_type or "requirements.txt"

    content = req.file_content or ""
    if req.file_path and os.path.exists(req.file_path):
        target_name = req.file_path
        with open(req.file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

    if req.file_type == "nodejs" or target_name.endswith(".json"):
        findings = dep_scanner.scan_package_json(content)
    else:
        findings = dep_scanner.scan_requirements_txt(content)

    duration = round(time.time() - start_time, 2)
    summary = calculate_summary(findings)

    result = ScanResult(
        scan_id=scan_id,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        scan_type="Software Composition Analysis (SCA)",
        target=target_name,
        status="completed",
        duration_seconds=duration,
        summary=summary,
        findings=findings
    )
    SCAN_STORE[scan_id] = result
    return result

# ----------------- AI CHATBOT ENDPOINT -----------------

@app.post("/api/chat", response_model=ChatResponse)
async def chat_with_agent(req: ChatRequest):
    active_scan = None
    if req.context_scan_id and req.context_scan_id in SCAN_STORE:
        active_scan = SCAN_STORE[req.context_scan_id]
    elif SCAN_STORE:
        # Pick the most recent scan if context_scan_id wasn't specified
        active_scan = list(SCAN_STORE.values())[-1]

    response = ai_agent.respond(req, active_scan=active_scan)
    return response

# ----------------- SCAN HISTORY & EXPORTS -----------------

@app.get("/api/scans/history", response_model=List[ScanResult])
async def get_scan_history():
    return list(SCAN_STORE.values())[::-1]

@app.get("/api/scans/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return SCAN_STORE[scan_id]

@app.get("/api/scans/{scan_id}/export-html", response_class=HTMLResponse)
async def export_html(scan_id: str):
    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = SCAN_STORE[scan_id]

    rows = ""
    for f in scan.findings:
        badge_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6",
            "INFO": "#64748b"
        }.get(f.severity.value, "#64748b")

        rows += f"""
        <tr style="border-bottom: 1px solid #334155;">
            <td style="padding: 12px;"><span style="background:{badge_color}; color:#fff; padding:4px 8px; border-radius:4px; font-weight:bold; font-size:12px;">{f.severity.value}</span></td>
            <td style="padding: 12px; font-weight:600;">{f.title}<br><small style="color:#94a3b8;">{f.category} | {f.cwe or ''}</small></td>
            <td style="padding: 12px; color:#cbd5e1; font-size:13px;">{f.description}<br><code style="color:#38bdf8; display:block; margin-top:4px;">{f.evidence or ''}</code></td>
            <td style="padding: 12px; color:#a7f3d0; font-size:13px;">{f.remediation}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>VulnGuard Audit Report - {scan.target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; }}
        .header {{ border-bottom: 2px solid #38bdf8; padding-bottom: 15px; margin-bottom: 25px; }}
        .summary-cards {{ display: flex; gap: 15px; margin-bottom: 30px; }}
        .card {{ background: #1e293b; padding: 15px 20px; border-radius: 8px; flex: 1; text-align: center; border: 1px solid #334155; }}
        .card h3 {{ margin: 0; font-size: 28px; color: #38bdf8; }}
        .card p {{ margin: 5px 0 0; color: #94a3b8; font-size: 13px; text-transform: uppercase; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th {{ background: #0f172a; padding: 12px; text-align: left; color: #94a3b8; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ VulnGuard Security Audit Report</h1>
        <p><strong>Target:</strong> {scan.target} | <strong>Scan Type:</strong> {scan.scan_type} | <strong>Date:</strong> {scan.timestamp}</p>
    </div>
    <div class="summary-cards">
        <div class="card"><h3>{scan.summary.risk_score}/100</h3><p>Risk Score</p></div>
        <div class="card"><h3 style="color:#ef4444;">{scan.summary.critical_count}</h3><p>Critical</p></div>
        <div class="card"><h3 style="color:#f97316;">{scan.summary.high_count}</h3><p>High</p></div>
        <div class="card"><h3 style="color:#eab308;">{scan.summary.medium_count}</h3><p>Medium</p></div>
        <div class="card"><h3 style="color:#3b82f6;">{scan.summary.low_count}</h3><p>Low</p></div>
    </div>
    <h2>Vulnerability Findings ({scan.summary.total_findings})</h2>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Vulnerability</th>
                <th>Description & Evidence</th>
                <th>Remediation</th>
            </tr>
        </thead>
        <tbody>
            {rows if rows else '<tr><td colspan="4" style="padding:20px; text-align:center; color:#94a3b8;">No vulnerabilities discovered. Clean scan!</td></tr>'}
        </tbody>
    </table>
    <div style="margin-top: 30px; color:#64748b; font-size:12px; text-align:center;">
        Generated by VulnGuard AI Security Scanner & Assistant
    </div>
</body>
</html>"""
    return HTMLResponse(content=html)

# Explicit root route for serverless & cloud deployments (Vercel, Render, etc.)
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    static_index = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(static_index):
        with open(static_index, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h2>VulnGuard AI is running. Static files missing.</h2>")

# Serve Static UI files (CSS, JS, assets)
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    # Mount sub-paths for direct assets
    css_dir = os.path.join(static_dir, "css")
    js_dir = os.path.join(static_dir, "js")
    if os.path.exists(css_dir):
        app.mount("/css", StaticFiles(directory=css_dir), name="css_static")
    if os.path.exists(js_dir):
        app.mount("/js", StaticFiles(directory=js_dir), name="js_static")
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static_root")

