#!/usr/bin/env python3
"""Bootstrap AutoRecon dependencies on Kali Linux / Debian-based Linux.

Run from the repository root: python3 setup.py
Creates .venv in this repository, installs Python modules into it, installs
missing apt packages and Go tools, then prints a dependency status summary.
This script installs dependencies only; it never launches reconnaissance.
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
VENV_BIN = VENV_DIR / "bin"
VENV_PYTHON = VENV_BIN / "python"
GO_BIN = Path(os.environ.get("GOBIN") or (Path.home() / "go" / "bin"))
REQUIREMENTS = ROOT / "requirements-api.txt"

APT_PACKAGES = {
    "git": ("git", "git"),
    "curl": ("curl", "curl"),
    "jq": ("jq", "jq"),
    "coreutils": ("tee", "tee"),
    "python3": ("python3", "python3"),
    "python3-venv": (None, "python3-venv"),
    "python3-pip": (None, "python3-pip"),
    "golang-go": ("go", "go"),
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
RESULTS = {}


def run(command, *, env=None, capture=False):
    try:
        return subprocess.run(
            [str(part) for part in command], cwd=str(ROOT), env=env,
            text=True, stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None, check=False,
        )
    except OSError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def command_exists(name):
    return shutil.which(name) is not None


def installed_apt_package(package):
    format_arg = "-f=" + "$" + "{Status}"
    result = run(["dpkg-query", "-W", format_arg, package], capture=True)
    return result.returncode == 0 and "install ok installed" in (result.stdout or "")


def install_apt_packages(packages):
    if not packages:
        return True
    prefix = [] if os.geteuid() == 0 else (["sudo"] if command_exists("sudo") else None)
    if prefix is None:
        print("[!] Root/sudo is required to install: " + ", ".join(packages))
        return False
    print("\n[+] Updating apt package indexes...")
    if run(prefix + ["apt-get", "update"]).returncode != 0:
        print("[!] apt-get update failed.")
        return False
    print("[+] Installing missing packages: " + ", ".join(packages))
    return run(prefix + ["apt-get", "install", "-y"] + packages).returncode == 0


def ensure_system_packages():
    print("\n=== System prerequisites ===")
    missing = []
    for package, (command, label) in APT_PACKAGES.items():
        present = installed_apt_package(package) if command is None else command_exists(command)
        if present:
            RESULTS[label] = ("OK", "already available")
        else:
            missing.append(package)
            RESULTS[label] = ("PENDING", "installing via apt")
    install_apt_packages(missing)
    for package in missing:
        command, label = APT_PACKAGES[package]
        present = installed_apt_package(package) if command is None else command_exists(command)
        RESULTS[label] = ("INSTALLED" if present else "FAILED",
                          "installed via apt" if present else "apt package unavailable")


def ensure_venv():
    print("\n=== Project Python environment ===")
    print("[+] Virtual environment path: {}".format(VENV_DIR))
    if VENV_DIR.exists() and not VENV_PYTHON.exists():
        print("[!] .venv exists but is incomplete. Rename/remove it, then rerun setup.")
        RESULTS["Python virtual environment"] = ("FAILED", "incomplete .venv")
        return False
    if not VENV_PYTHON.exists():
        try:
            venv.EnvBuilder(with_pip=True).create(str(VENV_DIR))
            RESULTS["Python virtual environment"] = ("INSTALLED", str(VENV_DIR))
        except Exception as exc:
            RESULTS["Python virtual environment"] = ("FAILED", str(exc))
            print("[!] Could not create .venv: {}".format(exc))
            return False
    else:
        RESULTS["Python virtual environment"] = ("OK", str(VENV_DIR))
    return True


def install_python_modules():
    if not ensure_venv():
        RESULTS["Python modules"] = ("FAILED", "virtual environment unavailable")
        return
    print("[+] Upgrading pip inside .venv...")
    run([VENV_PYTHON, "-m", "pip", "install", "--upgrade", "pip"])
    if REQUIREMENTS.exists():
        command = [VENV_PYTHON, "-m", "pip", "install", "-r", REQUIREMENTS]
    else:
        command = [VENV_PYTHON, "-m", "pip", "install", "requests>=2.31.0", "PyYAML>=6.0.1"]
    print("[+] Installing API-mode Python dependencies...")
    ok = run(command).returncode == 0

    for package, executable in (
        ("dirsearch", "dirsearch"),
        ("git+https://github.com/aboul3la/Sublist3r.git", "sublist3r"),
    ):
        if (VENV_BIN / executable).exists():
            print("[+] {} already installed.".format(executable))
            continue
        print("[+] Installing {} into .venv...".format(executable))
        if run([VENV_PYTHON, "-m", "pip", "install", package]).returncode != 0:
            print("[!] Could not install {}. See output above.".format(executable))
            ok = False

    check = run([VENV_PYTHON, "-c", "import requests, yaml; print('Python imports OK')"])
    ok = ok and check.returncode == 0
    RESULTS["Python modules"] = ("INSTALLED" if ok else "FAILED", str(VENV_DIR))


def ensure_go_path():
    GO_BIN.mkdir(parents=True, exist_ok=True)
    if str(GO_BIN) not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = str(GO_BIN) + os.pathsep + os.environ.get("PATH", "")
    bashrc = Path.home() / ".bashrc"
    line = 'export PATH="$PATH:$(go env GOPATH)/bin"'
    try:
        current = bashrc.read_text(encoding="utf-8") if bashrc.exists() else ""
        if line not in current:
            with bashrc.open("a", encoding="utf-8") as handle:
                handle.write("\n# AutoRecon Go tools\n" + line + "\n")
            print("[+] Added Go bin path to {}".format(bashrc))
    except OSError as exc:
        print("[!] Could not update {}: {}".format(bashrc, exc))


def install_go_tools():
    print("\n=== Go reconnaissance tools ===")
    if not command_exists("go"):
        for name in GO_TOOLS:
            RESULTS[name] = ("FAILED", "Go is unavailable")
        return
    ensure_go_path()
    for name, module in GO_TOOLS.items():
        binary = GO_BIN / name
        if command_exists(name) or binary.exists():
            RESULTS[name] = ("OK", shutil.which(name) or str(binary))
            print("[+] {} already installed.".format(name))
            continue
        print("[+] Installing {}...".format(name))
        result = run(["go", "install", module])
        if result.returncode == 0 and binary.exists():
            RESULTS[name] = ("INSTALLED", str(binary))
        else:
            RESULTS[name] = ("FAILED", "go install failed; inspect output above")


def print_summary():
    print("\n" + "=" * 74)
    print("AutoRecon setup summary")
    print("=" * 74)
    for name, (status, detail) in RESULTS.items():
        print("[{:<9}] {:<27} {}".format(status, name, detail))
    print("-" * 74)
    print("Repository             : {}".format(ROOT))
    print("Python virtualenv      : {}".format(VENV_DIR))
    print("Virtualenv interpreter : {}".format(VENV_PYTHON))
    print("Go binary directory    : {}".format(GO_BIN))
    print("\nActivate with: source {}/bin/activate".format(VENV_DIR))
    print("Then run: python autoRecon.py -h")
    print("Amass is intentionally omitted because its enumeration step was removed.")
    print("This setup script does not run any scans.")


def main():
    print("AutoRecon setup for Kali Linux / WSL2")
    print("Repository: {}".format(ROOT))
    if not sys.platform.startswith("linux") or not (ROOT / "autoRecon.py").is_file():
        print("[!] Run this script from the root of your AutoRecon Linux checkout.")
        return 2
    ensure_system_packages()
    install_python_modules()
    install_go_tools()

    os.environ["PATH"] = str(VENV_BIN) + os.pathsep + str(GO_BIN) + os.pathsep + os.environ.get("PATH", "")
    for name in ("dirsearch", "sublist3r"):
        path = shutil.which(name)
        RESULTS[name] = ("OK", path) if path else ("FAILED", "executable not found in project .venv")

    print_summary()
    failures = [name for name, (status, _detail) in RESULTS.items()
                if status in ("FAILED", "PARTIAL", "PENDING")]
    if failures:
        print("\n[!] Setup completed with issues: " + ", ".join(failures))
        print("[!] Fix the reported issues and rerun: python3 setup.py")
        return 1
    print("\n[+] All checked dependencies are available.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
