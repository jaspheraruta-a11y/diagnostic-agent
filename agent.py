import ctypes
import os
import json
import requests
import winreg
import time
import uuid
import platform
import psutil
import wmi
import win32evtlog
from datetime import datetime, timezone
from supabase import create_client, Client

# ==========================================================
# 1. SUPABASE CONFIGURATION & CLIENT SETUP
# ==========================================================
SUPABASE_URL = "https://powcalvodkxrkjjlogof.supabase.co"
SUPABASE_KEY = "sb_publishable_hkJQm1Ji7ZmjSKqlzFV-gA_GR-_bnt0"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
wmi_client = wmi.WMI()

# Tracking sets and globals for stateful detection
connected_usbs = set()
logged_warnings = set()
known_installed_apps = set()
initial_app_scan_done = False
ANCHOR_FILE = "device_anchor.json"

# ==========================================================
# 2. DEVICE HARDWARE FINGERPRINTING & ENROLLMENT
# ==========================================================
def get_mac_address() -> str:
    """Returns the unique physical MAC address of the active network adapter."""
    node = uuid.getnode()
    mac = ':'.join(('%012X' % node)[i:i+2] for i in range(0, 12, 2))
    return mac

def get_system_specs():
    """Extracts base system hardware specifications."""
    hostname = platform.node()
    os_name = f"{platform.system()} {platform.release()}"
    
    cpu_model = platform.processor()
    try:
        for cpu in wmi_client.Win32_Processor():
            cpu_model = cpu.Name.strip()
            break
    except Exception:
        pass

    total_ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)

    return {
        "hostname": hostname,
        "os_name": os_name,
        "cpu_model": cpu_model,
        "total_ram_gb": total_ram_gb,
    }

def register_device():
    """
    Registers the PC in Supabase or retrieves its existing record.
    Returns (device_id, baseline_ram_gb).
    """
    mac = get_mac_address()
    specs = get_system_specs()
    
    print(f"[*] Identifying system: {specs['hostname']} (MAC: {mac})")

    response = supabase.table("devices").select("id, total_ram_gb").eq("mac_address", mac).execute()
    now = datetime.now(timezone.utc).isoformat()

    if response.data and len(response.data) > 0:
        device_id = response.data[0]["id"]
        # Use originally registered RAM as baseline to detect RAM removal/theft
        baseline_ram = float(response.data[0].get("total_ram_gb") or specs["total_ram_gb"])
        
        supabase.table("devices").update({
            "hostname": specs["hostname"],
            "os_name": specs["os_name"],
            "cpu_model": specs["cpu_model"],
            "last_seen": now
        }).eq("id", device_id).execute()
        
        print(f"[+] Device registered. ID: {device_id} (Baseline RAM: {baseline_ram} GB)")
        return device_id, baseline_ram
    else:
        baseline_ram = specs["total_ram_gb"]
        insert_payload = {
            "mac_address": mac,
            "hostname": specs["hostname"],
            "os_name": specs["os_name"],
            "cpu_model": specs["cpu_model"],
            "total_ram_gb": baseline_ram,
            "last_seen": now
        }
        res = supabase.table("devices").insert(insert_payload).execute()
        device_id = res.data[0]["id"]
        print(f"[+] New device enrolled! ID: {device_id} (Baseline RAM: {baseline_ram} GB)")
        return device_id, baseline_ram

# ==========================================================
# 3. TELEMETRY, SENSORS & ACTIVE PROCESS HARVESTER
# ==========================================================
def check_smart_drive_status() -> bool:
    """Checks S.M.A.R.T. status of attached storage drives."""
    try:
        for disk in wmi_client.Win32_DiskDrive():
            if disk.Status and disk.Status.upper() != "OK":
                return True
        return False
    except Exception:
        return False

def get_cpu_temperature() -> float:
    """Reads CPU temperature via WMI or calculates a realistic dynamic estimate."""
    try:
        wmi_root = wmi.WMI(namespace="root\\wmi")
        zones = wmi_root.MSAcpi_ThermalZoneTemperature()
        if zones:
            temp_k = zones[0].CurrentTemperature / 10.0
            return round(temp_k - 273.15, 1)
    except Exception:
        pass
    
    load = psutil.cpu_percent()
    return round(42.0 + (load * 0.4), 1)

def get_running_applications():
    """Returns an alphabetically sorted list of running user applications, filtering out system threads."""
    system_blacklist = {
        'system idle process', 'system', 'registry', 'smss.exe', 'csrss.exe',
        'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'fontdrvhost.exe',
        'dwm.exe', 'spoolsv.exe', 'wlanext.exe', 'conhost.exe', 'taskhostw.exe',
        'sihost.exe', 'ctfmon.exe', 'shellexperiencehost.exe', 'searchindexer.exe',
        'runtimebroker.exe', 'startmenuexperiencehost.exe', 'securityhealthservice.exe',
        'msmpeng.exe', 'nissrv.exe', 'applicationframehost.exe'
    }
    apps = set()
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info['name']
            if name and name.lower() not in system_blacklist:
                apps.add(name)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
            
    return sorted(list(apps), key=str.lower)

def collect_telemetry(device_id: str):
    """Gathers dynamic performance metrics and active user applications."""
    cpu_pct = psutil.cpu_percent(interval=1)
    ram_pct = psutil.virtual_memory().percent
    
    try:
        disk_pct = psutil.disk_usage('C:\\').percent
    except Exception:
        disk_pct = 0.0

    cpu_temp = get_cpu_temperature()
    smart_failure = check_smart_drive_status()
    running_apps = get_running_applications()

    return {
        "device_id": device_id,
        "cpu_usage_pct": cpu_pct,
        "ram_usage_pct": ram_pct,
        "disk_usage_pct": disk_pct,
        "cpu_temp_c": cpu_temp,
        "smart_failure_predicted": smart_failure,
        "running_processes": running_apps,
        "recorded_at": datetime.now(timezone.utc).isoformat()
    }

# ==========================================================
# 4. HARDWARE TAMPERING & RAM THEFT DETECTOR
# ==========================================================
def check_hardware_tampering(device_id: str, baseline_ram: float):
    """Detects if RAM modules have been physically removed or failed."""
    current_ram = round(psutil.virtual_memory().total / (1024 ** 3), 2)
    
    # Trigger if missing 1.5 GB or more compared to registration baseline
    if baseline_ram and (baseline_ram - current_ram) >= 1.5:
        details = f"HARDWARE TAMPERING DETECTED: System RAM dropped from {baseline_ram} GB to {current_ram} GB! A RAM module may have been removed or died."
        
        existing = supabase.table("activity_logs") \
            .select("id") \
            .eq("device_id", device_id) \
            .eq("event_type", "HARDWARE_TAMPER") \
            .execute()
            
        if not existing.data or len(existing.data) == 0:
            now_iso = datetime.now(timezone.utc).isoformat()
            
            # 1. Log incident to activity_logs
            supabase.table("activity_logs").insert({
                "device_id": device_id,
                "event_type": "HARDWARE_TAMPER",
                "details": details,
                "recorded_at": now_iso
            }).execute()
            
            # 2. Dispatch Critical Maintenance Ticket
            supabase.table("maintenance_tickets").insert({
                "device_id": device_id,
                "issue_title": "Hardware Tampering: Missing RAM Module",
                "severity": "Critical",
                "status": "Open"
            }).execute()
            
            print(f"[!] CRITICAL ALERT: {details}")

# ==========================================================
# 5. STOLEN DRIVE & MOTHERBOARD MISMATCH DETECTOR
# ==========================================================
def check_stolen_drive_tampering(current_mac: str, current_hostname: str):
    """
    Detects if this hard drive was physically moved to another computer.
    Uses a persistent local anchor file compared against physical motherboard MAC.
    """
    if not os.path.exists(ANCHOR_FILE):
        anchor_data = {
            "original_mac": current_mac,
            "original_hostname": current_hostname,
            "enrolled_at": datetime.now(timezone.utc).isoformat()
        }
        with open(ANCHOR_FILE, "w") as f:
            json.dump(anchor_data, f, indent=2)
        print(f"[*] Drive anchored to host: {current_hostname} (MAC: {current_mac})")
        return

    try:
        with open(ANCHOR_FILE, "r") as f:
            anchor_data = json.load(f)

        original_mac = anchor_data.get("original_mac")
        original_hostname = anchor_data.get("original_hostname")

        # IF MAC DOES NOT MATCH: The hard drive was moved to an unauthorized PC!
        if original_mac and original_mac != current_mac:
            try:
                thief_ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
            except Exception:
                thief_ip = "Unknown IP (Offline/Restricted)"

            details = (
                f"CRITICAL ASSET THEFT: Hard drive originally registered to '{original_hostname}' (MAC: {original_mac}) "
                f"was booted on an unauthorized computer (New Host: '{current_hostname}', MAC: {current_mac})! "
                f"Active Public IP: {thief_ip}"
            )

            res = supabase.table("devices").select("id").eq("mac_address", original_mac).execute()
            if res.data and len(res.data) > 0:
                original_device_id = res.data[0]["id"]

                existing = supabase.table("activity_logs") \
                    .select("id") \
                    .eq("device_id", original_device_id) \
                    .eq("event_type", "STOLEN_DRIVE_ALERT") \
                    .execute()

                if not existing.data or len(existing.data) == 0:
                    now_iso = datetime.now(timezone.utc).isoformat()

                    supabase.table("activity_logs").insert({
                        "device_id": original_device_id,
                        "event_type": "STOLEN_DRIVE_ALERT",
                        "details": details,
                        "recorded_at": now_iso
                    }).execute()

                    supabase.table("maintenance_tickets").insert({
                        "device_id": original_device_id,
                        "issue_title": f"STOLEN DRIVE ACTIVE (IP: {thief_ip})",
                        "severity": "Critical",
                        "status": "Open"
                    }).execute()

                    print(f"\n[🚨 CRITICAL SECURITY ALERT 🚨]")
                    print(f"{details}\n")
    except Exception as e:
        print(f"[!] Stolen drive check error: {e}")

# ==========================================================
# 6. CRASH & BSOD AUDITING
# ==========================================================
def check_recent_crashes(device_id: str):
    """Audits Windows Event Logs for Kernel-Power (Event ID 41 / BSODs)."""
    try:
        hand = win32evtlog.OpenEventLog(None, "System")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        
        for event in events:
            if event.EventID & 0xFFFF == 41:
                event_time = event.TimeGenerated.Format()
                details = f"Unexpected Shutdown or BSOD detected (Event ID 41) at {event_time}"
                
                existing = supabase.table("activity_logs") \
                    .select("id") \
                    .eq("device_id", device_id) \
                    .eq("event_type", "BSOD") \
                    .eq("details", details) \
                    .execute()
                    
                if not existing.data or len(existing.data) == 0:
                    supabase.table("activity_logs").insert({
                        "device_id": device_id,
                        "event_type": "BSOD",
                        "details": details,
                        "recorded_at": datetime.now(timezone.utc).isoformat()
                    }).execute()
                    print(f"[!] Logged crash event: {details}")
                break
        win32evtlog.CloseEventLog(hand)
    except Exception:
        pass

# ==========================================================
# 7. RECENTLY INSTALLED APPS DETECTOR
# ==========================================================
def get_installed_software():
    """Reads installed applications from the Windows Registry."""
    apps = {}
    reg_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
    ]

    for root, subkey in reg_paths:
        try:
            with winreg.OpenKey(root, subkey) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        app_guid = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, app_guid) as app_key:
                            name, _ = winreg.QueryValueEx(app_key, "DisplayName")
                            if name and name.strip():
                                try:
                                    version, _ = winreg.QueryValueEx(app_key, "DisplayVersion")
                                except Exception:
                                    version = ""
                                try:
                                    install_date, _ = winreg.QueryValueEx(app_key, "InstallDate")
                                except Exception:
                                    install_date = ""
                                
                                apps[name.strip()] = {
                                    "version": version,
                                    "install_date": install_date
                                }
                    except Exception:
                        continue
        except Exception:
            continue
    return apps

def check_new_installed_apps(device_id: str):
    """Detects software installed recently or while the agent is running."""
    global known_installed_apps, initial_app_scan_done
    current_apps = get_installed_software()
    now_iso = datetime.now(timezone.utc).isoformat()
    today_str = datetime.now().strftime("%Y%m%d")

    # On first run, record apps installed today
    if not initial_app_scan_done:
        for app_name, info in current_apps.items():
            if info["install_date"] == today_str:
                details = f"Recent software installed: {app_name} (v{info['version']})"
                existing = supabase.table("activity_logs") \
                    .select("id") \
                    .eq("device_id", device_id) \
                    .eq("event_type", "APP_INSTALL") \
                    .eq("details", details) \
                    .execute()
                if not existing.data or len(existing.data) == 0:
                    supabase.table("activity_logs").insert({
                        "device_id": device_id,
                        "event_type": "APP_INSTALL",
                        "details": details,
                        "recorded_at": now_iso
                    }).execute()
                    print(f"[!] Logged recent install: {details}")

        known_installed_apps = set(current_apps.keys())
        initial_app_scan_done = True
        return

    # Continuous Monitoring: Detect software installed while agent is running
    new_apps = set(current_apps.keys()) - known_installed_apps
    for app_name in new_apps:
        version = current_apps[app_name]["version"]
        details = f"New software installed: {app_name}" + (f" (v{version})" if version else "")
        
        supabase.table("activity_logs").insert({
            "device_id": device_id,
            "event_type": "APP_INSTALL",
            "details": details,
            "recorded_at": now_iso
        }).execute()
        print(f"[!] ALERT: New app installed: {details}")

    known_installed_apps = set(current_apps.keys())

# ==========================================================
# 8. EXPANDED ACTIVITY DETECTORS (USB, Disk, CPU Spikes)
# ==========================================================
def audit_major_activities(device_id: str):
    """Monitors USB insertions, Low Disk Space, and Heavy Process Anomalies."""
    global connected_usbs, logged_warnings
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Detect USB Flash Drives
    try:
        current_usbs = {disk.DeviceID: disk.Caption for disk in wmi_client.Win32_DiskDrive() if disk.InterfaceType == "USB"}
        new_usbs = set(current_usbs.keys()) - connected_usbs
        for dev_id in new_usbs:
            name = current_usbs[dev_id]
            supabase.table("activity_logs").insert({
                "device_id": device_id,
                "event_type": "USB_INSERT",
                "details": f"Removable storage connected: {name}",
                "recorded_at": now_iso
            }).execute()
            print(f"[!] Activity: USB Plugged in ({name})")
        connected_usbs = set(current_usbs.keys())
    except Exception:
        pass

    # 2. Detect Low Disk Space (< 10% free space remaining)
    try:
        disk = psutil.disk_usage('C:\\')
        free_gb = round(disk.free / (1024**3), 2)
        if disk.percent >= 90.0:
            warn_key = f"disk_low_{datetime.now().strftime('%Y-%m-%d')}"
            if warn_key not in logged_warnings:
                supabase.table("activity_logs").insert({
                    "device_id": device_id,
                    "event_type": "DISK_WARNING",
                    "details": f"Low Disk Space Warning: Drive C: has only {free_gb} GB ({100 - disk.percent}%) remaining!",
                    "recorded_at": now_iso
                }).execute()
                logged_warnings.add(warn_key)
                print(f"[!] Activity: Low Disk Space alert logged.")
    except Exception:
        pass

    # 3. Detect Heavy CPU Processes (> 70% CPU usage)
    try:
        for proc in psutil.process_iter(['name', 'cpu_percent']):
            try:
                if proc.info['cpu_percent'] and proc.info['cpu_percent'] > 70.0:
                    proc_name = proc.info['name']
                    if proc_name.lower() not in ['system idle process', 'idle']:
                        supabase.table("activity_logs").insert({
                            "device_id": device_id,
                            "event_type": "PROCESS_SPIKE",
                            "details": f"High Resource Consumption: '{proc_name}' is utilizing {proc.info['cpu_percent']}% CPU.",
                            "recorded_at": now_iso
                        }).execute()
                        print(f"[!] Activity: Heavy process detected ({proc_name})")
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass

# ==========================================================
# 9. TWO-WAY REMOTE COMMAND DISPATCHER
# ==========================================================
def check_and_execute_commands(device_id: str):
    """Polls Supabase for PENDING administrative commands and executes them locally."""
    try:
        response = supabase.table("device_commands") \
            .select("*") \
            .eq("device_id", device_id) \
            .eq("status", "PENDING") \
            .execute()

        if not response.data or len(response.data) == 0:
            return

        for cmd in response.data:
            cmd_id = cmd["id"]
            action = cmd["command"]
            payload = cmd.get("payload") or ""
            now_iso = datetime.now(timezone.utc).isoformat()

            print(f"\n[⚡ REMOTE COMMAND RECEIVED] Action: {action} | Payload: {payload}")
            success = False
            audit_detail = ""

            try:
                # ACTION 1: LOCK WORKSTATION
                if action == "LOCK":
                    print("[*] Locking Windows screen now...")
                    ctypes.windll.user32.LockWorkStation()
                    success = True
                    audit_detail = "Remote action: Workstation locked by IT Administrator."

                # ACTION 2: RESTART PC
                elif action == "RESTART":
                    print("[*] Initiating system restart in 5 seconds...")
                    os.system("shutdown /r /t 5 /f /c \"Remote reboot initiated by IT Admin\"")
                    success = True
                    audit_detail = "Remote action: System restart initiated by IT Administrator."

                # ACTION 3: TERMINATE RUNAWAY PROCESS
                elif action == "KILL_PROCESS" and payload:
                    target = payload.strip().lower()
                    killed_count = 0
                    for proc in psutil.process_iter(['name']):
                        try:
                            if proc.info['name'] and proc.info['name'].lower() == target:
                                proc.kill()
                                killed_count += 1
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    if killed_count > 0:
                        success = True
                        audit_detail = f"Remote action: Terminated {killed_count} instance(s) of '{payload}'."
                    else:
                        success = False
                        audit_detail = f"Remote action failed: Process '{payload}' was not running."

            except Exception as cmd_err:
                success = False
                audit_detail = f"Failed to execute command '{action}': {cmd_err}"

            # Update command record status in Supabase
            new_status = "EXECUTED" if success else "FAILED"
            supabase.table("device_commands").update({
                "status": new_status,
                "executed_at": now_iso
            }).eq("id", cmd_id).execute()

            # Log to activity_logs for permanent audit trail
            supabase.table("activity_logs").insert({
                "device_id": device_id,
                "event_type": "REMOTE_ACTION",
                "details": audit_detail,
                "recorded_at": now_iso
            }).execute()

            print(f"[+] Command {action} -> {new_status}: {audit_detail}")

    except Exception as e:
        print(f"[!] Remote command error: {e}")

# ==========================================================
# 10. MAIN EXECUTION LOOP
# ==========================================================
def main():
    print("==================================================")
    print(" SmartBench Endpoint Diagnostic Agent Initialized")
    print("==================================================")
    
    try:
        device_id, baseline_ram = register_device()
    except Exception as e:
        print(f"[!] Failed to register with Supabase: {e}")
        return

    # Check if this hard drive was moved to an unauthorized PC
    current_mac = get_mac_address()
    current_hostname = platform.node()
    check_stolen_drive_tampering(current_mac, current_hostname)

    # Check for past BSOD crashes on startup
    check_recent_crashes(device_id)

    print("[*] Monitoring started. Sending telemetry & auditing activities...")
    print("[*] Press Ctrl + C to stop.\n")

    while True:
        try:
            # 1. Check & execute any pending commands from Admin Portal
            check_and_execute_commands(device_id)

            # 2. Check for Hardware Tampering / Stolen RAM modules
            check_hardware_tampering(device_id, baseline_ram)

            # 3. Audit newly installed software
            check_new_installed_apps(device_id)

            # 4. Audit USBs, Low Disk Space, and Process Spikes
            audit_major_activities(device_id)

            # 5. Collect CPU, RAM, Temp, S.M.A.R.T. & Active Running Apps
            telemetry = collect_telemetry(device_id)
            
            # Upsert telemetry (1 row per device to keep database lightweight)
            supabase.table("telemetry_logs").upsert(telemetry, on_conflict="device_id").execute()

            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"Heartbeat Sent -> CPU: {telemetry['cpu_usage_pct']}% | "
                  f"RAM: {telemetry['ram_usage_pct']}% | "
                  f"Temp: {telemetry['cpu_temp_c']}°C | "
                  f"Apps Detected: {len(telemetry['running_processes'])} | "
                  f"SMART: {'FAIL' if telemetry['smart_failure_predicted'] else 'OK'}")

            # 6. Wait 10 seconds before next scan
            time.sleep(10)

        except KeyboardInterrupt:
            print("\n[!] Agent stopped by user.")
            break
        except Exception as e:
            print(f"[!] Telemetry loop error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()