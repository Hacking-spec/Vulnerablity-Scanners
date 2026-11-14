// VulnGuard AI — Interactive Chatbot & Security Assistant Module

class VulnGuardChat {
    constructor() {
        this.messages = [];
        this.drawer = document.getElementById("chat-drawer");
        this.messagesContainer = document.getElementById("chat-messages");
        this.form = document.getElementById("chat-form");
        this.input = document.getElementById("chat-input");
        this.contextPill = document.getElementById("chat-scan-context-pill");
        this.contextName = document.getElementById("chat-context-name");
        this.contextFindings = document.getElementById("chat-context-findings");

        this.provider = localStorage.getItem("vg_ai_provider") || "offline";
        this.apiKey = localStorage.getItem("vg_ai_key") || "";
        this.activeScan = null;

        this.initEventListeners();
        this.updateProviderBadge();
    }

    initEventListeners() {
        // Toggle chat drawer
        const toggleBtn = document.getElementById("btn-toggle-chat");
        const closeBtn = document.getElementById("btn-close-chat");

        if (toggleBtn) {
            toggleBtn.addEventListener("click", () => this.toggleDrawer());
        }
        if (closeBtn) {
            closeBtn.addEventListener("click", () => this.closeDrawer());
        }

        // Form submission
        if (this.form) {
            this.form.addEventListener("submit", (e) => {
                e.preventDefault();
                const text = this.input.value.trim();
                if (text) {
                    this.sendMessage(text);
                    this.input.value = "";
                }
            });
        }

        // Quick suggestion chips
        document.querySelectorAll(".chat-chip").forEach(chip => {
            chip.addEventListener("click", () => {
                const prompt = chip.getAttribute("data-prompt");
                if (prompt) {
                    this.openDrawer();
                    this.sendMessage(prompt);
                }
            });
        });

        // Settings modal
        const settingsBtn = document.getElementById("btn-settings");
        const settingsModal = document.getElementById("settings-modal");
        const closeSettingsBtn = document.getElementById("btn-close-settings");
        const saveSettingsBtn = document.getElementById("btn-save-settings");
        const providerSelect = document.getElementById("setting-provider");
        const apiKeyGroup = document.getElementById("group-api-key");
        const apiKeyInput = document.getElementById("setting-api-key");

        if (settingsBtn && settingsModal) {
            settingsBtn.addEventListener("click", () => {
                providerSelect.value = this.provider;
                apiKeyInput.value = this.apiKey;
                apiKeyGroup.style.display = this.provider === "offline" ? "none" : "block";
                settingsModal.style.display = "flex";
            });

            closeSettingsBtn.addEventListener("click", () => {
                settingsModal.style.display = "none";
            });

            providerSelect.addEventListener("change", (e) => {
                apiKeyGroup.style.display = e.target.value === "offline" ? "none" : "block";
            });

            saveSettingsBtn.addEventListener("click", () => {
                this.provider = providerSelect.value;
                this.apiKey = apiKeyInput.value.trim();
                localStorage.setItem("vg_ai_provider", this.provider);
                localStorage.setItem("vg_ai_key", this.apiKey);
                this.updateProviderBadge();
                settingsModal.style.display = "none";
            });
        }
    }

    updateProviderBadge() {
        const badge = document.getElementById("current-provider-badge");
        if (badge) {
            const names = {
                offline: "Offline Expert",
                gemini: "Gemini 2.5 Flash",
                openai: "GPT-4o Mini",
                groq: "Groq LLaMA 3.3"
            };
            badge.textContent = names[this.provider] || this.provider;
        }
    }

    toggleDrawer() {
        this.drawer.classList.toggle("collapsed");
    }

    openDrawer() {
        this.drawer.classList.remove("collapsed");
    }

    closeDrawer() {
        this.drawer.classList.add("collapsed");
    }

    setScanContext(scan) {
        this.activeScan = scan;
        if (scan) {
            this.contextName.textContent = scan.target;
            this.contextFindings.textContent = `${scan.summary.total_findings} findings`;
            this.contextPill.style.display = "flex";
        }
    }

    appendMessage(role, text) {
        const msgDiv = document.createElement("div");
        msgDiv.className = `chat-msg ${role}`;

        if (role === "assistant") {
            try {
                // Parse markdown
                msgDiv.innerHTML = marked.parse(text);

                // Add copy buttons to code blocks
                msgDiv.querySelectorAll("pre").forEach(pre => {
                    const copyBtn = document.createElement("button");
                    copyBtn.className = "btn btn-secondary btn-sm";
                    copyBtn.style.position = "absolute";
                    copyBtn.style.top = "6px";
                    copyBtn.style.right = "6px";
                    copyBtn.style.padding = "2px 6px";
                    copyBtn.style.fontSize = "0.7rem";
                    copyBtn.textContent = "📋 Copy";

                    copyBtn.addEventListener("click", () => {
                        const code = pre.querySelector("code") ? pre.querySelector("code").innerText : pre.innerText;
                        navigator.clipboard.writeText(code).then(() => {
                            copyBtn.textContent = "✓ Copied!";
                            setTimeout(() => { copyBtn.textContent = "📋 Copy"; }, 2000);
                        });
                    });

                    pre.style.position = "relative";
                    pre.appendChild(copyBtn);
                });

            } catch (e) {
                msgDiv.textContent = text;
            }
        } else {
            msgDiv.textContent = text;
        }

        this.messagesContainer.appendChild(msgDiv);
        this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
        this.messages.push({ role, content: text });
        return msgDiv;
    }

    async sendMessage(text) {
        this.appendMessage("user", text);

        // Show typing placeholder
        const typingEl = document.createElement("div");
        typingEl.className = "chat-msg assistant";
        typingEl.innerHTML = `
            <div style="display:flex; align-items:center; gap:8px;">
                <span style="display:inline-block; width:8px; height:8px; background:#06b6d4; border-radius:50%; animation: pulseGlow 1s infinite alternate;"></span>
                <em>SentinelAI is analyzing security context...</em>
            </div>
        `;
        this.messagesContainer.appendChild(typingEl);
        this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;

        try {
            const payload = {
                message: text,
                conversation_history: this.messages.slice(-6),
                context_scan_id: this.activeScan ? this.activeScan.scan_id : null,
                provider: this.provider,
                api_key: this.apiKey || null
            };

            const resp = await fetch("/api/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!resp.ok) {
                throw new Error(`HTTP ${resp.status}`);
            }

            const data = await resp.json();
            typingEl.remove();

            const assistantMsg = this.appendMessage("assistant", data.reply);

            // Add action suggestions if present
            if (data.suggested_actions && data.suggested_actions.length > 0) {
                const actionsContainer = document.createElement("div");
                actionsContainer.style.marginTop = "0.85rem";
                actionsContainer.style.display = "flex";
                actionsContainer.style.flexWrap = "wrap";
                actionsContainer.style.gap = "0.4rem";

                data.suggested_actions.forEach(actionText => {
                    const btn = document.createElement("button");
                    btn.className = "btn btn-secondary btn-sm";
                    btn.style.fontSize = "0.74rem";
                    btn.style.padding = "0.25rem 0.6rem";
                    btn.textContent = `💡 ${actionText}`;
                    btn.addEventListener("click", () => this.sendMessage(actionText));
                    actionsContainer.appendChild(btn);
                });

                assistantMsg.appendChild(actionsContainer);
            }

        } catch (err) {
            typingEl.remove();
            this.appendMessage("assistant", `⚠️ Failed to get response from security agent: ${err.message}. Please check connection.`);
        }
    }
}

// Global chat instance
window.vulnChat = new VulnGuardChat();
