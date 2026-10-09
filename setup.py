#!/usr/bin/env python3
"""Install AutoRecon's Kali/Linux command-line tools and Python dependencies.

Run from the repository root:
    python3 setup.py

This is an interactive environment bootstrapper, not a Python package build script.
It creates .venv inside the repository, installs Python modules there, installs
system packages through apt when needed, and installs Go tools into GOPATH/bin.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path


ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
VENV_PYTHON = VENV_DIR / "bin" / "python"
GO_BIN = Path.home() / "go" / "bin"

APT_PACKAGES = {
    "curl": "curl",
    "jq": "jq",
    "tee": "coreutils",
}
GO_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
}
PYTHON_TOOLS = ("sublist3r", "dirsearch")
OTHER_COMMANDS = ("git", "python3", "go")


def run(command, *, env=None, check=False, capture=False):
    """Run a command without shell interpolation."""
    try:
        return subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            check=check,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
    except OSError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def command_exists(command):
    return shutil.which(command) is not None


def sudo_available():
    return os.geteuid() == 0 or command_exists("sudo")


def install_apt_packages(packages):
    if not packages:
        return True
    if not sudo_available():
        print("[!] Need root or sudo to install apt packages: " + ", ".join(packages))
        return False
    prefix = [] if os.geteuid() == 0 else ["sudo"]
    print("[*] Installing system packages: " + ", ".join(packages))
    update = run(prefix + ["apt-get", "update"])
    if update.returncode != 0:
        print("[!] apt-get update failed.")
        return False
    result = run(prefix + ["apt-get", "install", "-y"] + packages)
    return result.returncode == 0


def ensure_venv():
    if not VENV_PYTHON.exists():
        print(f"[*] Creating project virtual environment: {VENV_DIR}")
        venv.EnvBuilder(with_pip=True).create(VENV_DIR)
    else:
        print(f"[+] Reusing project virtual environment: {VENV_DIR}")
    return VENV_PYTHON.exists()


def install_python_dependencies():
    if not ensure_venv():
        return False
    print("[*] Upgrading pip in project virtual environment...")
    upgrade = run([str(VENV_PYTHON), "-m", "pip", "install", "--upgrade", "pip"])
    if upgrade.returncode != 0:
        print("[!] Could not upgrade pip; continuing with dependency installation.")
    requirements = ROOT / "requirements-api.txt"
    if requirements.exists():
        result = run([str(VENV_PYTHON), "-m", "pip", "install", "-r", str(requirements)])
        if result.returncode != 0:
            print("[!] Installing requirements-api.txt failed.")
            return False
    else:
        result = run([
            str(VENV_PYTHON), "-m", "pip", "install", "requests>=2.31.0", "PyYAML>=6.0.1"
        ])
        if result.returncode != 0:
            return False

    # dirsearch's executable is invoked by the existing general-recon workflow.
    for package in PYTHON_TOOLS:
        if package == "sublist3r":
            # The legacy package may fail on newer Python versions; report that explicitly.
            check = run([str(VENV_PYTHON), "-m", "pip", "show", "sublist3r"], capture=True)
            if check.returncode == 0:
                print("[+] Python tool already installed: sublist3r")
                continue
            print("[*] Installing Sublist3r into .venv (legacy dependency; may not support every Python version)...")
            result = run([
                str(VENV_PYTHON), "-m", "pip", "install",
                "git+https://github.com/aboul3la/Sublist3r.git"
            ])
            if result.returncode != 0:
                print("[!] Sublist3r installation failed. Other setup steps will continue.")
        elif package == "dirsearch":
            if shutil.which(str(VENV_DIR / "bin" / "dirsearch")):
                print("[+] Python tool already installed: dirsearch")
                continue
            print("[*] Installing dirsearch into .venv...")
            result = run([str(VENV_PYTHON), "-m", "pip", "install", "dirsearch"])
            if result.returncode != 0:
                print("[!] dirsearch installation failed.")
    return True


def install_go_tool(name, module):
    binary = GO_BIN / name
    if command_exists(name) or binary.exists():
        print(f"[+] {name} already installed.")
        return True
    if not command_exists("go"):
        print(f"[!] Cannot install {name}: Go is not installed.")
        return False
    print(f"[*] Installing {name} with go install...")
    env = os.environ.copy()
    env["PATH"] = str(GO_BIN) + os.pathsep + env.get("PATH", "")
    result = run(["go", "install", module], env=env)
    if result.returncode != 0 or not binary.exists():
        print(f"[!] Installation failed for {name}.")
        return False
    print(f"[+] Installed {name}: {binary}")
    return True


def main():
    print("=" * 64)
    print("AutoRecon setup — Kali Linux / Debian-based Linux")
    print(f"Repository: {ROOT}")
    print("=" * 64)

    if not (ROOT / "autoRecon.py").exists():
        print("[!] Run this script from a valid AutoRecon checkout.")
        return 2
    if not sys.platform.startswith("linux"):
        print("[!] This setup script currently targets Kali/Linux.")
        return 2

    summary = {}
    missing_apt = [package for command, package in APT_PACKAGES.items() if not command_exists(command)]
    apt_ok = install_apt_packages(sorted(set(missing_apt))) if missing_apt else True
    for command, package in APT_PACKAGES.items():
        summary[command] = command_exists(command)
        if not summary[command] and not apt_ok:
            print(f"[!] {command} remains unavailable.")

    # The Go tools install into ~/go/bin by default. Add it to the current setup
    # process and persist PATH for future interactive Bash sessions.
    GO_BIN.mkdir(parents=True, exist_ok=True)
    env_path = os.environ.get("PATH", "")
    if str(GO_BIN) not in env_path.split(os.pathsep):
        os.environ["PATH"] = str(GO_BIN) + os.pathsep + env_path

    if command_exists("go"):
        bashrc = Path.home() / ".bashrc"
        path_line = 'export PATH="$PATH:$(go env GOPATH)/bin"'
        try:
            current = bashrc.read_text(encoding="utf-8") if bashrc.exists() else ""
            if path_line not in current:
                with bashrc.open("a", encoding="utf-8") as handle:
                    handle.write("\n# AutoRecon Go tools\n" + path_line + "\n")
                print(f"[+] Added Go binary directory to {bashrc}")
        except OSError as exc:
            print(f"[!] Could not update {bashrc}: {exc}")

    python_ok = install_python_dependencies()
    summary["Python venv + modules"] = python_ok

    for name, module in GO_TOOLS.items():
        summary[name] = install_go_tool(name, module)

    for command in OTHER_COMMANDS:
        summary[command] = command_exists(command)

    # Re-check all commands after installations, including commands from .venv.
    venv_bin = VENV_DIR / "bin"
    os.environ["PATH"] = str(venv_bin) + os.pathsep + str(GO_BIN) + os.pathsep + os.environ.get("PATH", "")
    for command in ("sublist3r", "dirsearch"):
        summary[command] = command_exists(command)

    print("\n" + "=" * 64)
    print("AutoRecon setup summary")
    print("=" * 64)
    for name, ok in summary.items():
        print(f"[{'OK' if ok else 'MISSING'}] {name}")
    print(f"\nPython virtual environment: {VENV_DIR}")
    print(f"Python interpreter: {VENV_PYTHON}")
    print(f"Activate with: source {VENV_DIR}/bin/activate")
    print("Go tools directory: " + str(GO_BIN))
    print("\nNote: this setup does not install Amass; the current AutoRecon workflow removed it.")
    print("Review any [MISSING] entries above before running reconnaissance.")
    return 0 if all(summary.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
