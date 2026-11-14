"""
VulnGuard AI - Entry Point Launcher
"""
import sys
import os
import uvicorn

# Ensure the root directory is on the python search path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 8000))

    print("=" * 65)
    print("🛡️  VulnGuard AI - Vulnerability Scanner & Security AI Agent")
    print("=" * 65)
    print(f"🚀 Server starting at: http://{host}:{port}")
    print("🌐 Open the URL in your browser to access the dashboard & AI chatbot.")
    print("=" * 65)

    uvicorn.run("app.main:app", host=host, port=port, reload=False, log_level="info")

if __name__ == "__main__":
    main()

