from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ScanType(str, Enum):
    WEB = "web"
    CODE = "code"
    PORTS = "ports"
    DEPENDENCIES = "dependencies"
    FULL = "full"

class VulnerabilityFinding(BaseModel):
    id: str
    title: str
    severity: SeverityLevel
    category: str
    description: str
    evidence: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    url: Optional[str] = None
    cwe: Optional[str] = None
    owasp_category: Optional[str] = "A05:2021-Security Misconfiguration"
    remediation: str
    cvss_score: Optional[float] = 0.0

class ScanSummary(BaseModel):
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    total_findings: int = 0
    risk_score: float = 0.0
    owasp_breakdown: Dict[str, int] = {}

class ScanResult(BaseModel):
    scan_id: str
    timestamp: str
    scan_type: str
    target: str
    status: str
    duration_seconds: float
    summary: ScanSummary
    findings: List[VulnerabilityFinding] = []

class ChatMessage(BaseModel):
    role: str
    content: str
    timestamp: Optional[str] = None

class ChatRequest(BaseModel):
    message: str
    conversation_history: Optional[List[ChatMessage]] = []
    context_scan_id: Optional[str] = None
    provider: Optional[str] = "offline"
    api_key: Optional[str] = None

class ChatResponse(BaseModel):
    reply: str
    suggested_actions: Optional[List[str]] = []
    references: Optional[List[str]] = []

class WebScanRequest(BaseModel):
    url: str
    check_ssl: bool = True
    check_headers: bool = True
    check_sensitive_paths: bool = True
    check_cors: bool = True

class CodeScanRequest(BaseModel):
    directory_path: Optional[str] = None
    code_content: Optional[str] = None
    file_name: Optional[str] = "snippet.py"

class PortScanRequest(BaseModel):
    host: str
    port_range: Optional[str] = "common"  # "common", "web", "database", or "1-1024"

class DependencyScanRequest(BaseModel):
    file_content: Optional[str] = None
    file_type: Optional[str] = "python"  # "python" (requirements.txt) or "nodejs" (package.json)
    file_path: Optional[str] = None

class PatchRequest(BaseModel):
    finding_id: str
    code_content: str
    file_name: Optional[str] = "snippet.py"

class PatchResponse(BaseModel):
    finding_id: str
    original_code: str
    remediated_code: str
    diff_summary: str
    explanation: str
