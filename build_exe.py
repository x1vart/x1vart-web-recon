"""
x1vart Standalone Executable Builder
Packages the entire FastAPI backend, Static Dashboard, and Desktop GUI Window into a single portable binary (.exe).
"""

import os
import sys
import subprocess

def build():
    try:
        import PyInstaller
    except ImportError:
        print("[*] PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    sep = ";" if os.name == "nt" else ":"
    
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name=x1vart",
        "--onefile",
        "--noconsole",
        f"--add-data=static{sep}static",
        "--hidden-import=uvicorn.logging",
        "--hidden-import=uvicorn.loops",
        "--hidden-import=uvicorn.loops.auto",
        "--hidden-import=uvicorn.protocols",
        "--hidden-import=uvicorn.protocols.http",
        "--hidden-import=uvicorn.protocols.http.auto",
        "--hidden-import=uvicorn.protocols.websockets",
        "--hidden-import=uvicorn.protocols.websockets.auto",
        "--hidden-import=uvicorn.lifespan",
        "--hidden-import=uvicorn.lifespan.on",
        "--hidden-import=bs4",
        "--hidden-import=dns",
        "--hidden-import=dns.resolver",
        "--hidden-import=paramiko",
        "--clean",
        "-y",
        "app.py"
    ]

    print("[*] Running PyInstaller Desktop App build:")
    print(" ".join(cmd))
    result = subprocess.run(cmd)

    if result.returncode == 0:
        print("\n========================================================")
        print("  Build Success! Standalone Desktop App ready:")
        target_path = os.path.abspath('dist/x1vart.exe' if os.name == 'nt' else 'dist/x1vart')
        print(f"  -> {target_path}")
        print("========================================================")
    else:
        print("\n[!] Build failed. Check errors above.")
        sys.exit(result.returncode)

if __name__ == "__main__":
    build()
