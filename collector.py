import psutil
import os
import platform
import subprocess
from datetime import datetime

# ── System Info ─────────────────────────────────────────────────────────────
def get_system_info():
    print("[*] Collecting system information...")
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

# ── Running Processes ────────────────────────────────────────────────────────
def get_running_processes():
    print("[*] Collecting running processes...")
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(processes, key=lambda x: x['memory_percent'] or 0, reverse=True)

# ── Network Connections ──────────────────────────────────────────────────────
def get_network_connections():
    print("[*] Collecting network connections...")
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            connections.append({
                "pid": conn.pid,
                "status": conn.status,
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
            })
        except Exception:
            continue
    return connections

# ── User Accounts ────────────────────────────────────────────────────────────
def get_user_accounts():
    print("[*] Collecting user accounts...")
    try:
        result = subprocess.run(["net", "user"], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

# ── Startup Programs ─────────────────────────────────────────────────────────
def get_startup_programs():
    print("[*] Collecting startup programs...")
    try:
        result = subprocess.run(
            ["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
            capture_output=True, text=True
        )
        return result.stdout
    except Exception as e:
        return str(e)

# ── Recently Modified Files ──────────────────────────────────────────────────
def get_recent_files(directory="C:\\Users", hours=24):
    print("[*] Collecting recently modified files...")
    recent = []
    cutoff = datetime.now().timestamp() - (hours * 3600)
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ['AppData', 'node_modules', '.git']]
        for file in files:
            try:
                filepath = os.path.join(root, file)
                mtime = os.path.getmtime(filepath)
                if mtime > cutoff:
                    recent.append({
                        "file": filepath,
                        "modified": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                    })
            except Exception:
                continue
    return sorted(recent, key=lambda x: x['modified'], reverse=True)[:50]

# ── Run All Collections ──────────────────────────────────────────────────────
def collect_all():
    print("\n=== IR Toolkit - Evidence Collector ===\n")
    data = {
        "system_info": get_system_info(),
        "processes": get_running_processes(),
        "network_connections": get_network_connections(),
        "user_accounts": get_user_accounts(),
        "startup_programs": get_startup_programs(),
        "recent_files": get_recent_files(),
    }
    print("\n[✓] Collection complete!")
    return data