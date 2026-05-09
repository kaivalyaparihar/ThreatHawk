import subprocess
import sys
import os
import time
import webbrowser
from threading import Timer

ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ROOT, "backend")
FRONTEND_DIR = os.path.join(ROOT, "frontend")
PYTHON = os.path.join(BACKEND_DIR, "venv", "Scripts", "python.exe")

def open_browser():
    time.sleep(8)
    webbrowser.open("http://localhost:3000")

print("🦅 Starting ThreatHawk...")
print("   Backend  → http://localhost:8000")
print("   Frontend → http://localhost:3000")
print("   Press Ctrl+C to stop everything\n")

# Start backend first
backend = subprocess.Popen(
    [PYTHON, "main.py"],
    cwd=BACKEND_DIR,
)

# Wait for backend to be ready before starting frontend
print("   Waiting for backend to start...")
time.sleep(6)

# Start frontend
frontend = subprocess.Popen(
    ["npm", "run", "dev"],
    cwd=FRONTEND_DIR,
    shell=True,
)

# Open browser after frontend is ready
Timer(1, open_browser).start()

try:
    backend.wait()
except KeyboardInterrupt:
    print("\n🛑 Shutting down ThreatHawk...")
    backend.terminate()
    frontend.terminate()
    sys.exit(0)