// VulnGuard AI — Enterprise Controller & Interactive Dashboard Logic

let currentScanResult = null;
let currentFilter = "ALL";

document.addEventListener("DOMContentLoaded", () => {
    initNavigationTabs();
    initSampleLoaders();
    initDragAndDrop();
    initScannerForms();
    initScanActions();
    initFilters();
});

// Tab Navigation
function initNavigationTabs() {
    const tabs = document.querySelectorAll(".nav-tab");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");

            const targetPaneId = tab.getAttribute("data-tab");
            document.querySelectorAll(".tab-pane").forEach(pane => {
                pane.style.display = pane.id === targetPaneId ? "block" : "none";
            });

            if (targetPaneId === "history-tab") {
                loadHistory();
            }
        });
    });
}

// Quick Sample Loaders & Target Pills
function initSampleLoaders() {
    // 1. Web Quick Targets
    document.querySelectorAll(".sample-chip[data-url]").forEach(chip => {
        chip.addEventListener("click", () => {
            const urlInput = document.getElementById("web-url");
            urlInput.value = chip.getAttribute("data-url");
            urlInput.focus();
        });
    });

    // 2. Port Quick Targets
    document.querySelectorAll(".sample-chip[data-host]").forEach(chip => {
        chip.addEventListener("click", () => {
            const hostInput = document.getElementById("port-host");
            hostInput.value = chip.getAttribute("data-host");
            hostInput.focus();
        });
    });

    // 3. Vulnerable Code Sample
    const sampleCodeBtn = document.getElementById("btn-load-vulnerable-sample");
    if (sampleCodeBtn) {
        sampleCodeBtn.addEventListener("click", () => {
            const fakeStripe = "sk_" + "live_" + "245981298412093840192849";
            const sample = `# Vulnerable Demo Application - VulnGuard Test Suite
import os
import pickle
import hashlib
import sqlite3
import requests

# 1. Hardcoded Secret Key (Critical)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
STRIPE_SECRET_KEY = "${fakeStripe}"

def search_users(user_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # 2. SQL Injection vulnerability (Critical)
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()

def run_diagnostic(target_ip):
    # 3. OS Command Injection (Critical)
    os.system(f"ping -c 1 {target_ip}")

def load_session_state(user_cookie):
    # 4. Insecure Deserialization (High)
    return pickle.loads(user_cookie)

def hash_password(password):
    # 5. Broken cryptographic hash (Medium)
    return hashlib.md5(password.encode()).hexdigest()

def fetch_remote_metrics():
    # 6. Disabled SSL verification (High)
    resp = requests.get("https://internal.metrics.local/api", verify=False)
    return resp.json()

if __name__ == "__main__":
    # 7. Framework debug active (Medium)
    DEBUG = True
    print("Vulnerable server running...")
`;
            document.getElementById("code-input").value = sample;
            document.getElementById("code-filename").value = "vulnerable_app.py";
        });
    }

    // 4. Scan current directory button
    const scanCurrentDirBtn = document.getElementById("btn-scan-current-dir");
    if (scanCurrentDirBtn) {
        scanCurrentDirBtn.addEventListener("click", async () => {
            await executeScan("/api/scan/code", {
                directory_path: "."
            }, scanCurrentDirBtn, "Auditing project directory...", "code");
        });
    }

    // 5. Vulnerable Dependencies Sample
    const sampleDepsBtn = document.getElementById("btn-load-sample-deps");
    if (sampleDepsBtn) {
        sampleDepsBtn.addEventListener("click", () => {
            const sample = `# requirements.txt with known vulnerable versions
requests==2.28.1
urllib3==1.26.5
django==3.2.0
flask==2.1.2
pyyaml==5.3.1
pillow==9.5.0
cryptography==41.0.2
werkzeug==2.2.3
`;
            document.getElementById("deps-content").value = sample;
            document.getElementById("deps-type").value = "python";
        });
    }
}

// Drag & Drop Code Files
function initDragAndDrop() {
    const dropzone = document.getElementById("code-dropzone");
    const fileInput = document.getElementById("file-code-upload");

    if (!dropzone || !fileInput) return;

    dropzone.addEventListener("click", () => fileInput.click());

    ["dragenter", "dragover"].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add("dragover");
        }, false);
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove("dragover");
        }, false);
    });

    dropzone.addEventListener("drop", (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            handleFileSelect(files[0]);
        }
    });

    fileInput.addEventListener("change", (e) => {
        if (fileInput.files.length > 0) {
            handleFileSelect(fileInput.files[0]);
        }
    });
}

function handleFileSelect(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        document.getElementById("code-input").value = e.target.result;
        document.getElementById("code-filename").value = file.name;
    };
    reader.readAsText(file);
}

// Scanner Form Submissions
function initScannerForms() {
    // Web Scan Form
    const webForm = document.getElementById("form-scan-web");
    if (webForm) {
        webForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const btn = document.getElementById("btn-scan-web");
            const url = document.getElementById("web-url").value.trim();
            const payload = {
                url: url,
                check_ssl: document.getElementById("chk-ssl").checked,
                check_headers: document.getElementById("chk-headers").checked,
                check_sensitive_paths: document.getElementById("chk-paths").checked,
                check_cors: document.getElementById("chk-cors").checked
            };
            await executeScan("/api/scan/web", payload, btn, "Auditing web endpoint...", "web");
        });
    }

    // Code Scan Form
    const codeForm = document.getElementById("form-scan-code");
    if (codeForm) {
        codeForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const btn = document.getElementById("btn-scan-code");
            const codeContent = document.getElementById("code-input").value;
            const fileName = document.getElementById("code-filename").value.trim() || "snippet.py";

            if (!codeContent.trim()) {
                alert("Please paste code or load sample code to scan.");
                return;
            }

            const payload = {
                code_content: codeContent,
                file_name: fileName
            };
            await executeScan("/api/scan/code", payload, btn, "Analyzing source code...", "code");
        });
    }

    // Ports Scan Form
    const portForm = document.getElementById("form-scan-ports");
    if (portForm) {
        portForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const btn = document.getElementById("btn-scan-ports");
            const host = document.getElementById("port-host").value.trim();
            const range = document.getElementById("port-range").value;
            const payload = {
                host: host,
                port_range: range
            };
            await executeScan("/api/scan/ports", payload, btn, "Scanning open ports...", "ports");
        });
    }

    // Dependencies Scan Form
    const depsForm = document.getElementById("form-scan-deps");
    if (depsForm) {
        depsForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const btn = document.getElementById("btn-scan-deps");
            const content = document.getElementById("deps-content").value;
            const type = document.getElementById("deps-type").value;

            if (!content.trim()) {
                alert("Please paste manifest content or load sample requirements.");
                return;
            }

            const payload = {
                file_content: content,
                file_type: type
            };
            await executeScan("/api/scan/dependencies", payload, btn, "Checking CVE database...", "deps");
        });
    }
}

// Generic scan executor with terminal logging
async function executeScan(endpoint, payload, triggerBtn, loadingText, termKey) {
    const originalText = triggerBtn.innerHTML;
    triggerBtn.disabled = true;
    triggerBtn.innerHTML = `⏳ ${loadingText}`;

    // Show Terminal simulation
    const term = document.getElementById(`term-${termKey}`);
    const termBody = document.getElementById(`term-body-${termKey}`);
    if (term && termBody) {
        term.style.display = "block";
        termBody.innerHTML = `[+] Initiating VulnGuard audit engine on target...\n[+] Sending non-intrusive probe requests...\n`;
    }

    try {
        const resp = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!resp.ok) {
            const err = await resp.json();
            throw new Error(err.detail || `Server returned error ${resp.status}`);
        }

        const data = await resp.json();
        currentScanResult = data;

        if (termBody) {
            termBody.innerHTML += `[+] Inspection complete in ${data.duration_seconds}s.\n[✓] Audit finished: ${data.summary.total_findings} findings detected. Risk Score: ${data.summary.risk_score}/100\n`;
            termBody.scrollTop = termBody.scrollHeight;
        }

        renderScanResults(data);

        // Update chatbot context
        if (window.vulnChat) {
            window.vulnChat.setScanContext(data);
        }

    } catch (err) {
        if (termBody) {
            termBody.innerHTML += `[!] Error executing audit: ${err.message}\n`;
        }
        alert(`Scan failed: ${err.message}`);
    } finally {
        triggerBtn.disabled = false;
        triggerBtn.innerHTML = originalText;
    }
}

// Render Results & Animate Risk Gauge
function renderScanResults(result) {
    const container = document.getElementById("scan-results-container");
    container.style.display = "block";
    container.scrollIntoView({ behavior: "smooth" });

    // Meta details
    document.getElementById("res-target-title").textContent = result.target;
    document.getElementById("res-meta-info").textContent =
        `Type: ${result.scan_type} | Duration: ${result.duration_seconds}s | Scan ID: ${result.scan_id} | Completed: ${result.timestamp}`;

    // Risk Meter & Gauge Arc
    const score = result.summary.risk_score;
    document.getElementById("risk-score-display").textContent = score;

    const circleBar = document.getElementById("risk-circle-bar");
    const circumference = 251.2;
    const offset = circumference - (circumference * score / 100);
    circleBar.style.strokeDashoffset = offset;

    // Shift color according to risk score (Standard normal colors)
    let strokeColor = "#16a34a"; // Low / Safe Green
    let postureTitle = "Strong Security Posture (Low Risk)";
    let postureDesc = "No severe vulnerabilities detected. Follow defense-in-depth principles to maintain this posture.";

    if (score >= 70) {
        strokeColor = "#dc2626"; // Standard Red
        postureTitle = "Critical Risk Exposure Detected";
        postureDesc = "High-impact vulnerabilities require immediate remediation to prevent unauthorized compromise.";
    } else if (score >= 40) {
        strokeColor = "#ea580c"; // Standard Orange
        postureTitle = "Elevated Risk Posture (High Risk)";
        postureDesc = "Significant vulnerabilities discovered. Prioritize remediation of high-severity findings before deployment.";
    } else if (score >= 20) {
        strokeColor = "#d97706"; // Standard Amber
        postureTitle = "Moderate Risk Posture (Medium Risk)";
        postureDesc = "Security hygiene improvements recommended to prevent escalation.";
    }

    circleBar.style.stroke = strokeColor;
    document.getElementById("risk-posture-title").textContent = postureTitle;
    document.getElementById("risk-posture-title").style.color = strokeColor;
    document.getElementById("risk-posture-desc").textContent = postureDesc;

    // KPIs
    document.getElementById("kpi-critical").textContent = result.summary.critical_count;
    document.getElementById("kpi-high").textContent = result.summary.high_count;
    document.getElementById("kpi-medium").textContent = result.summary.medium_count;
    document.getElementById("kpi-low").textContent = result.summary.low_count;
    document.getElementById("kpi-info").textContent = result.summary.info_count;
    document.getElementById("findings-count").textContent = result.findings.length;

    renderFindingsList();
}

// Render Findings List with Filtering
function renderFindingsList() {
    if (!currentScanResult) return;

    const findingsContainer = document.getElementById("findings-container");
    findingsContainer.innerHTML = "";

    const filtered = currentScanResult.findings.filter(f => {
        if (currentFilter === "ALL") return true;
        return f.severity === currentFilter;
    });

    if (filtered.length === 0) {
        findingsContainer.innerHTML = `
            <div style="text-align: center; padding: 2.5rem; color: #166534; background: #f0fdf4; border-radius: var(--radius-md); border: 1px solid #bbf7d0;">
                <div style="font-size: 1.75rem; margin-bottom: 0.35rem;">✓</div>
                <h4 style="font-size: 1.05rem; font-weight: 700; color: #166534;">No vulnerabilities detected for this criteria</h4>
                <p style="color: #4b5563; font-size: 0.85rem; margin-top: 4px;">All evaluated security controls passed the inspection.</p>
            </div>
        `;
        return;
    }

    filtered.forEach(finding => {
        const item = document.createElement("div");
        item.className = `finding-item ${finding.severity.toLowerCase()}`;

        const badgeClass = `badge-${finding.severity.toLowerCase()}`;

        item.innerHTML = `
            <div class="finding-header">
                <div>
                    <span class="badge ${badgeClass}">${finding.severity}</span>
                    <strong class="finding-title" style="margin-left: 0.5rem;">${finding.title}</strong>
                    <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">
                        Category: ${finding.category} ${finding.cwe ? `• ${finding.cwe}` : ''} ${finding.cvss_score ? `• Estimated CVSS: ${finding.cvss_score}` : ''}
                    </div>
                </div>
                <button class="btn btn-primary btn-sm btn-ask-ai-finding" data-finding-id="${finding.id}" data-finding-title="${finding.title}">
                    🤖 Ask AI to Fix
                </button>
            </div>

            <p class="finding-desc">${finding.description}</p>

            ${finding.evidence ? `
                <div class="finding-evidence">
                    <strong>Evidence / Snippet:</strong><br>${escapeHtml(finding.evidence)}
                </div>
            ` : ''}

            <div class="finding-remediation">
                <div>
                    <strong>🛡️ Remediation:</strong> ${finding.remediation}
                </div>
                <button class="btn btn-secondary btn-sm" onclick="copyRemediation('${escapeJs(finding.remediation)}')" style="white-space:nowrap; padding: 0.25rem 0.6rem; font-size: 0.72rem;">
                    📋 Copy Fix
                </button>
            </div>
        `;

        findingsContainer.appendChild(item);
    });

    // Attach click listeners to "Ask AI to Fix" buttons
    document.querySelectorAll(".btn-ask-ai-finding").forEach(btn => {
        btn.addEventListener("click", () => {
            const fId = btn.getAttribute("data-finding-id");
            const fTitle = btn.getAttribute("data-finding-title");
            if (window.vulnChat) {
                window.vulnChat.openDrawer();
                window.vulnChat.sendMessage(`How do I fix [${fId}]: "${fTitle}"? Provide step-by-step guidance and exact code fix.`);
            }
        });
    });
}

function copyRemediation(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert("Remediation advice copied to clipboard!");
    });
}

function initFilters() {
    const filterBtns = document.querySelectorAll("#filter-buttons button");
    filterBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            filterBtns.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentFilter = btn.getAttribute("data-filter");
            renderFindingsList();
        });
    });
}

function initScanActions() {
    // Export HTML
    const exportHtmlBtn = document.getElementById("btn-export-html");
    if (exportHtmlBtn) {
        exportHtmlBtn.addEventListener("click", () => {
            if (!currentScanResult) return;
            window.open(`/api/scans/${currentScanResult.scan_id}/export-html`, "_blank");
        });
    }

    // Export JSON
    const exportJsonBtn = document.getElementById("btn-export-json");
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener("click", () => {
            if (!currentScanResult) return;
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentScanResult, null, 2));
            const downloadAnchor = document.createElement("a");
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", `vulnguard_scan_${currentScanResult.scan_id}.json`);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        });
    }

    // Ask AI Summary
    const askAiSummaryBtn = document.getElementById("btn-ask-ai-summary");
    if (askAiSummaryBtn) {
        askAiSummaryBtn.addEventListener("click", () => {
            if (window.vulnChat) {
                window.vulnChat.openDrawer();
                window.vulnChat.sendMessage("Provide a prioritized remediation plan and security overview for all findings in this scan.");
            }
        });
    }
}

// Load Scan History
async function loadHistory() {
    const listEl = document.getElementById("history-list");
    try {
        const resp = await fetch("/api/scans/history");
        const history = await resp.json();

        if (history.length === 0) {
            listEl.innerHTML = `<p style="color: var(--text-dim); font-size: 0.875rem;">No scans recorded in this session yet.</p>`;
            return;
        }

        listEl.innerHTML = "";
        history.forEach(item => {
            const card = document.createElement("div");
            card.style.background = "rgba(11, 17, 32, 0.7)";
            card.style.border = "1px solid var(--border-subtle)";
            card.style.borderRadius = "var(--radius-md)";
            card.style.padding = "1.15rem";
            card.style.marginBottom = "0.75rem";
            card.style.display = "flex";
            card.style.justifyContent = "space-between";
            card.style.alignItems = "center";
            card.style.flexWrap = "wrap";
            card.style.gap = "0.75rem";

            card.innerHTML = `
                <div>
                    <strong style="color: #38bdf8; font-size: 1rem;">${item.target}</strong>
                    <span style="font-size: 0.75rem; color: var(--text-dim); margin-left: 0.5rem;">(${item.scan_type})</span>
                    <div style="font-size: 0.825rem; color: var(--text-muted); margin-top: 4px;">
                        Date: ${item.timestamp} | Findings: ${item.summary.total_findings} (🔴 ${item.summary.critical_count} | 🟠 ${item.summary.high_count} | 🟡 ${item.summary.medium_count})
                    </div>
                </div>
                <div style="display: flex; gap: 0.5rem;">
                    <button class="btn btn-secondary btn-sm" onclick="loadScanFromHistory('${item.scan_id}')">
                        View Results
                    </button>
                </div>
            `;
            listEl.appendChild(card);
        });
    } catch (e) {
        listEl.innerHTML = `<p style="color: #ef4444;">Failed to load history: ${e.message}</p>`;
    }
}

window.loadScanFromHistory = async function(scanId) {
    try {
        const resp = await fetch(`/api/scans/${scanId}`);
        const data = await resp.json();
        currentScanResult = data;
        renderScanResults(data);
        if (window.vulnChat) {
            window.vulnChat.setScanContext(data);
        }
    } catch (e) {
        alert("Failed to load scan: " + e.message);
    }
};

function escapeHtml(text) {
    if (!text) return "";
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function escapeJs(text) {
    if (!text) return "";
    return text.replace(/'/g, "\\'").replace(/"/g, '\\"');
}
