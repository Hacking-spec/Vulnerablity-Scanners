import sys
import os

# Add the project root to sys.path so 'app' can be imported by Vercel
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.main import app

# Vercel looks for the 'app' ASGI callable
handler = app

