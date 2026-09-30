import subprocess
import shutil

def check_local_system():
    """Audit local Linux system for updates and critical configuration details."""
    audit_results = {
        "os_release": "Unknown",
        "upgradable_packages": 0,
        "firewall_active": False
    }

    # Check Ubuntu OS Release
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    audit_results["os_release"] = line.split("=")[1].strip().strip('"')
    except Exception:
        pass

    # Check UFW Firewall Status
    if shutil.which("ufw"):
        try:
            res = subprocess.run(["sudo", "ufw", "status"], capture_output=True, text=True)
            if "status: active" in res.stdout.lower():
                audit_results["firewall_active"] = True
        except Exception:
            pass

    return audit_results