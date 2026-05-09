#backend\utils\tor_controller.py

import os
import subprocess
import time
import requests
from dotenv import load_dotenv

load_dotenv()

TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
_tor_process = None


def find_tor_exe():
    """Find tor.exe from common Windows locations or .env."""
    env_path = os.getenv("TOR_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    common_paths = [
        os.path.expandvars(r"%USERPROFILE%\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe"),
        os.path.expandvars(r"%PROGRAMFILES%\Tor Browser\Browser\TorBrowser\Tor\tor.exe"),
        os.path.expandvars(r"%PROGRAMFILES(X86)%\Tor Browser\Browser\TorBrowser\Tor\tor.exe"),
        os.path.expandvars(r"%APPDATA%\Tor Browser\Browser\TorBrowser\Tor\tor.exe"),
        os.path.expandvars(r"%USERPROFILE%\Downloads\Tor Browser\Browser\TorBrowser\Tor\tor.exe"),
        r"C:\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
    ]

    for path in common_paths:
        if os.path.exists(path):
            return path

    return None


def start_tor():
    """Start tor.exe as a subprocess. Returns True if started successfully."""
    global _tor_process

    # Check if already running by testing the SOCKS proxy
    if is_tor_running():
        print("[Tor] Tor is already running")
        return True

    tor_exe = find_tor_exe()
    if not tor_exe:
        print("[Tor] WARNING: tor.exe not found. Dark web features will be unavailable.")
        print("[Tor] Set TOR_PATH in .env or install Tor Browser.")
        return False

    try:
        _tor_process = subprocess.Popen(
            [tor_exe],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )

        # Wait for bootstrap
        for i in range(30):
            time.sleep(1)
            if is_tor_running():
                print("[Tor] Tor started successfully")
                return True

        print("[Tor] WARNING: Tor did not bootstrap in 30 seconds")
        return False

    except Exception as e:
        print(f"[Tor] ERROR starting tor: {e}")
        return False


def is_tor_running():
    """Check if Tor SOCKS proxy is accessible."""
    try:
        session = requests.Session()
        session.proxies = {
            "http": f"socks5h://127.0.0.1:{TOR_SOCKS_PORT}",
            "https": f"socks5h://127.0.0.1:{TOR_SOCKS_PORT}",
        }
        response = session.get("http://check.torproject.org", timeout=10)
        return response.status_code == 200
    except Exception:
        return False


def get_tor_session():
    """Returns a requests.Session with SOCKS5 proxy configured."""
    session = requests.Session()
    session.proxies = {
        "http": f"socks5h://127.0.0.1:{TOR_SOCKS_PORT}",
        "https": f"socks5h://127.0.0.1:{TOR_SOCKS_PORT}",
    }
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
    })
    return session


def rotate_circuit():
    """Request a new Tor circuit using stem."""
    try:
        from stem import Signal
        from stem.control import Controller

        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            print("[Tor] Circuit rotated")
            time.sleep(5)  # Wait for new circuit
            return True
    except Exception as e:
        print(f"[Tor] Circuit rotation failed: {e}")
        return False
