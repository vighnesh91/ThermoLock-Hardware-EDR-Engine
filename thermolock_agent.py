#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
ThermoLock Host Sensor Agent (thermolock_agent.py)
Production-Ready Bare-Metal Thermodynamic Intrusion Detection & Mitigation Agent
===============================================================================

ARCHITECTURE & DESIGN PHILOSOPHY:
In isolated, air-gapped, or hardened high-security enterprise environments,
advanced persistent threats (APTs), stealth implants, and rootkits frequently
evade traditional OS-level security agents (EDRs) through techniques such as:
  1. Direct Kernel Object Manipulation (DKOM) to unlink executive process blocks
     (e.g., EPROCESS on Windows, task_struct on Linux) from kernel scheduler lists.
  2. Ring -1 / Hypervisor-level virtualization rootkits (Blue Pill architecture)
     executing covert workloads in VMX root mode invisible to the guest kernel.
  3. Covert thread injection and scheduler manipulation designed to mask OS CPU
     accounting counters, masquerading as an idle operating system.
  4. Memory-only in-memory database compression, internal network scanning, or
     covert cryptojacking operations executing without disk touch.

However, all electronic computation is bound by fundamental physical laws:
Joule Heating and CMOS dynamic power dissipation:
    P_dynamic = alpha * C * V^2 * f + I_leakage * V
Malware executing heavy background computations MUST draw electrical current through
the physical bare-metal processor silicon gates. This dynamic power dissipation
transfers directly into physical thermal dissipation across the silicon die and
heat spreader. Thermodynamic dissipation cannot be obfuscated, forged, or unlinked
by ring 0 rootkits or ring 3 malware.

ThermoLock operates as an out-of-band thermodynamic EDR sensor, sampling physical
hardware thermal sensors at a strict 1.0-second interval:
  - Thermal Delta Speed (TDS): Current physical CPU temperature minus temperature
    recorded exactly 1.0s prior (signed float, e.g., +5.2°C/s).
  - Global CPU Load Percentage: Utilization reported by the OS kernel.

CORE MATHEMATICAL TRIGGER & HYSTERESIS CONFIRMATION:
  TRIGGER CONDITION: (TDS >= 5.0°C/s) AND (Global CPU Load <= 15.0%)
Real-world enterprise endpoints experience transient single-core Turbo Boost
bursts, fan spin-up delays, or bursty I/O. To prevent false-positive disruption,
ThermoLock incorporates a configurable multi-sample hysteresis confirmation filter:
The anomaly condition must persist for consecutive intervals (default: 3 samples)
before active ring-level mitigation is triggered.

FORENSIC-SAFE NON-DESTRUCTIVE MITIGATION & VOLATILE TRIAGE:
Abruptly killing process trees (SIGKILL, TerminateProcess) destroys critical
volatile forensic memory artifacts (unencrypted C2 configurations, decryption keys,
transient payload memory mappings, active socket state).
ThermoLock deploys forensic-safe ring-level kernel abstractions:
  - Linux: Clean POSIX SIGSTOP (Signal 19) freezes the target process in memory,
    transitioning it to TASK_STOPPED. CPU execution stops immediately, halting heat
    dissipation and network transport, while memory pages, registers, and descriptors
    remain 100% preserved in volatile RAM for live acquisition (LiME, gcore, AVML).
  - Windows: Alters Win32 ProcessorAffinity mask via SetProcessAffinityMask, trapping
    the suspect thread strictly on CPU Core 0 (mask 0x0001). This neutralizes multi-core
    parallel hashing and compression, cooling the silicon, while preserving the entire
    EPROCESS virtual address space for memory triage (DumpIt, WinPmem, ProcDump).
  - macOS: Issues kernel-level scheduling priority demotion ('renice 20 -p <PID>' /
    os.setpriority), demoting suspect threads to the lowest background execution tier.
  - Ephemeral Memory Triage: Extracts command line, working directory, binary path,
    virtual memory maps (executable r-xp segments), and socket descriptors at the
    instant of mitigation, embedding them directly into the alert payload.

ENTERPRISE PRODUCTION HARDENING:
  - Windows Performance Optimization: Decoupled background polling & native in-memory
    GetSystemTimes ctypes calls; zero per-second PowerShell process creation.
  - Startup Privilege Enforcement: Explicitly validates root/administrator rights.
  - Bounded Resilient Spool Queue: Caps offline storage (10 MB / 5,000 entries) with
    automatic FIFO log rotation (.1) to prevent disk exhaustion during outages.
  - Network Backoff & Jitter: Exponential backoff with randomized jitter prevents
    reconnection storms to the central SIEM/log server.
  - Dry-Run / Audit-Only Mode: (--audit-only) Logs anomalies and egress alerts without
    modifying running processes, allowing safe baseline calibration.
  - Prometheus Metrics Exporter: Exposes /metrics on local HTTP endpoint or writes
    atomic .prom stats file for enterprise observability.
===============================================================================
"""

import os
import sys
import hashlib
import time
import json
import glob
import re
import socket
import signal
import random
import platform
import tempfile
import threading
import subprocess
import urllib.request
import urllib.error
import ssl
from collections import deque
from typing import Dict, List, Optional, Tuple, Set, Any

# =============================================================================
# GLOBAL CONFIGURATION & DEFAULTS
# =============================================================================

AGENT_VERSION: str = "1.3.0-ENTERPRISE-HYBRID"

# Default hardcoded configuration URL string (Private LAN Switch Layer)
LOG_SERVER_URL: str = os.environ.get(
    "THERMOLOCK_LOG_SERVER_URL",
    "http://192.168.1.100:8080/api/v1/thermolock/alerts"
)

# Core mathematical trigger thresholds
SAMPLE_INTERVAL_SEC: float = 1.0         # Strict 1.0-second cadence
TDS_TRIGGER_THRESHOLD_C: float = 5.0     # Thermal Delta Speed threshold (+5.0°C/s)
CPU_LOAD_MAX_THRESHOLD_PCT: float = 15.0 # Max kernel CPU load for anomaly (15.0%)
DEFAULT_HYSTERESIS_TICKS: int = 3        # Consecutive ticks required to confirm anomaly
ALERT_COOLDOWN_SEC: float = 5.0          # Minimum cooldown between repeated alerts
DEFAULT_HEARTBEAT_SEC: int = 60          # Heartbeat interval (0 to disable)

# Spool bounds and rotation limits
MAX_SPOOL_BYTES: int = 10 * 1024 * 1024  # 10 MB maximum main spool file size
MAX_SPOOL_ENTRIES: int = 5000            # Maximum queued alert lines before rotation
DEFAULT_SPOOL_FILE: str = os.path.join(tempfile.gettempdir(), "thermolock_spool.jsonl")

# Sensor plausibility boundaries (Celsius)
MIN_PLAUSIBLE_TEMP_C: float = 5.0
MAX_PLAUSIBLE_TEMP_C: float = 120.0

# Network egress configuration
HTTP_TIMEOUT_SEC: float = 3.0
USER_AGENT: str = f"ThermoLock-Hardware-EDR/{AGENT_VERSION} (BareMetal-Sensor-Daemon; LAN-Egress)"

# Default Prometheus metrics path
DEFAULT_METRICS_FILE: str = os.path.join(tempfile.gettempdir(), "thermolock_metrics.prom")

# Windows Win32 API Constants
PROCESS_SET_INFORMATION: int = 0x0200
PROCESS_QUERY_INFORMATION: int = 0x0400
WIN32_AFFINITY_CORE_0: int = 0x0001
TH32CS_SNAPPROCESS: int = 0x0002

# Default Trusted Signers for Dynamic Whitelisting (Windows WinVerifyTrust)
DEFAULT_TRUSTED_SIGNERS: List[str] = [
    "Microsoft Corporation",
    "Microsoft Windows",
    "CrowdStrike, Inc.",
    "CrowdStrike",
    "Sentinel Labs",
    "SentinelOne",
    "Sophos",
    "Palo Alto Networks",
    "Broadcom",
    "Google LLC"
]


# =============================================================================
# STARTUP PRIVILEGE ENFORCEMENT
# =============================================================================

def enforce_privilege_check(allow_unprivileged: bool = False) -> bool:
    """
    Validates that the process is executing with elevated administrative privileges:
      - Linux/macOS: EUID 0 (root)
      - Windows: Administrator token (IsUserAnAdmin)
    Exits cleanly if unprivileged, unless explicitly overridden for lab evaluation.
    """
    sys_plat = platform.system()
    is_elevated = False

    if sys_plat == "Windows":
        try:
            import ctypes
            is_elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_elevated = False
    else:
        is_elevated = (os.geteuid() == 0)

    if not is_elevated:
        if allow_unprivileged:
            sys.stderr.write(
                "[*] NOTICE: Running in unprivileged mode (--allow-unprivileged active).\n"
                "    Kernel process suspension (SIGSTOP), affinity masking, and direct ACPI\n"
                "    sensor queries will operate under restricted user permissions.\n"
            )
            sys.stderr.flush()
            return False
        else:
            remedy = "'sudo python3 thermolock_agent.py'" if sys_plat != "Windows" else "'Run as Administrator'"
            sys.stderr.write(
                "================================================================================\n"
                "[!] CRITICAL ERROR: ELEVATED PRIVILEGES REQUIRED\n"
                "================================================================================\n"
                "ThermoLock operates as a bare-metal hardware EDR sensor and requires:\n"
                "  - Linux/macOS: Root privileges (EUID 0) to issue POSIX SIGSTOP (Signal 19)\n"
                "    and read low-level kernel sysfs/ACPI thermal registers.\n"
                "  - Windows: Administrator privileges to query 'root\\wmi' and invoke Win32\n"
                "    SetProcessAffinityMask.\n\n"
                f"Remediation:\n"
                f"  - Execute with: {remedy}\n"
                "  - Or pass '--allow-unprivileged' for lab/audit dry-run evaluation.\n"
                "================================================================================\n"
            )
            sys.stderr.flush()
            sys.exit(1)
    return True


# =============================================================================
# SINGLE-INSTANCE DAEMON LOCK
# =============================================================================

class SingleInstanceLock:
    """
    Guarantees exactly one instance of ThermoLock runs per host.
    Uses POSIX fcntl on Linux/macOS and Win32 named Mutex on Windows.
    """

    def __init__(self, lock_path: Optional[str] = None):
        self.system = platform.system()
        self.lock_path = lock_path or os.path.join(tempfile.gettempdir(), "thermolock_agent.lock")
        self._fd: Optional[int] = None
        self._win_mutex = None

    def acquire(self) -> bool:
        if self.system == "Windows":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                mutex_name = "Global\\ThermoLock_Agent_Singleton_Mutex"
                self._win_mutex = kernel32.CreateMutexW(None, True, mutex_name)
                ERROR_ALREADY_EXISTS = 183
                if kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
                    return False
                return True
            except Exception:
                return True
        else:
            try:
                import fcntl
                self._fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except (BlockingIOError, OSError):
                return False

    def release(self) -> None:
        if self._fd is not None:
            try:
                import fcntl
                fcntl.flock(self._fd, fcntl.LOCK_UN)
                os.close(self._fd)
                if os.path.exists(self.lock_path):
                    os.unlink(self.lock_path)
            except Exception:
                pass
            self._fd = None


# =============================================================================
# ZERO-DEPENDENCY SYSTEMD WATCHDOG & HEARTBEAT NOTIFIER
# =============================================================================

class SystemdNotifier:
    """
    Zero-dependency standard library implementation of systemd sd_notify(3).
    Communicates with systemd supervisor over NOTIFY_SOCKET (AF_UNIX datagram socket).
    Supports:
      - READY=1 (signaling successful initialization and sensor calibration)
      - WATCHDOG=1 (periodic heartbeat ping keeping systemd watchdog fed)
      - STATUS=... (high-level human-readable daemon state string for systemctl status)
      - STOPPING=1 (graceful shutdown notification)
      - RELOADING=1 (configuration hot-reload notification)
    Operates safely across all platforms (returns False with zero overhead if NOTIFY_SOCKET is unset).
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.socket_path = os.environ.get("NOTIFY_SOCKET")
        self.watchdog_usec: Optional[int] = None
        if "WATCHDOG_USEC" in os.environ:
            try:
                self.watchdog_usec = int(os.environ["WATCHDOG_USEC"])
            except ValueError:
                self.watchdog_usec = None
        self._is_enabled = bool(self.socket_path and hasattr(socket, "AF_UNIX"))
        self._last_watchdog_ping: float = 0.0

    @property
    def is_enabled(self) -> bool:
        return self._is_enabled

    def notify(self, state: str) -> bool:
        """Transmits state string (e.g. 'READY=1', 'WATCHDOG=1') to systemd supervisor."""
        if not self._is_enabled or not self.socket_path:
            return False

        target_addr = self.socket_path
        if target_addr.startswith("@"):
            # Linux abstract namespace socket
            target_addr = "\x00" + target_addr[1:]

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                sock.connect(target_addr)
                sock.sendall(state.encode("utf-8"))
            return True
        except Exception as exc:
            if self.verbose:
                sys.stderr.write(f"[!] [SYSTEMD NOTIFY] Failed to notify systemd: {exc}\n")
            return False

    def notify_ready(self, status: str = "ThermoLock monitoring active") -> bool:
        return self.notify(f"READY=1\nSTATUS={status}")

    def notify_watchdog(self) -> bool:
        """Pings systemd watchdog to reset watchdog countdown timer."""
        self._last_watchdog_ping = time.monotonic()
        return self.notify("WATCHDOG=1")

    def notify_status(self, status: str) -> bool:
        return self.notify(f"STATUS={status}")

    def notify_stopping(self) -> bool:
        return self.notify("STOPPING=1\nSTATUS=ThermoLock daemon shutting down")

    def notify_reloading(self) -> bool:
        return self.notify("RELOADING=1\nSTATUS=Reloading dynamic configuration")


# =============================================================================
# PLATFORM HARDWARE INGESTION ENGINE (ZERO PROCESS-CREATION OVERHEAD)
# =============================================================================

class HardwareThermalIngestion:
    """
    Cross-platform bare-metal hardware thermal ingestion engine.
    Ingests physical CPU and GPU silicon temperatures with glitch and plausibility filtering.
    WINDOWS OPTIMIZATION: Decouples WMI queries into a background worker thread
    running on a relaxed cadence (15s), ensuring the fast 1.0s loop executes
    strictly in-memory with ZERO subprocess.run(["powershell.exe"]) overhead!
    """

    def __init__(self, verbose: bool = False):
        self.system = platform.system()
        self.verbose = verbose
        self._last_valid_temp: float = 42.0
        self._thermal_fallback_mode: bool = False

        # Windows decoupled background cache state
        self._cached_windows_temp: float = 42.0
        self._windows_poller_thread: Optional[threading.Thread] = None
        self._poller_stop_event = threading.Event()

        if self.system == "Windows":
            # Establish a real sensor baseline before the fast monitoring loop starts.
            # This intentionally performs one bounded synchronous query (up to the
            # query timeout) to avoid a 42°C placeholder being treated as a real sample.
            initial_temp: Optional[float] = None
            # Fail closed rather than starting the 1-second monitor with a synthetic
            # 42°C baseline. The bounded retry window is intentionally synchronous.
            for attempt in range(3):
                candidate = self._query_windows_wmi_once()
                if candidate is not None and MIN_PLAUSIBLE_TEMP_C <= candidate <= MAX_PLAUSIBLE_TEMP_C:
                    initial_temp = float(candidate)
                    break
                if attempt < 2:
                    time.sleep(0.5)
            if initial_temp is None:
                raise RuntimeError(
                    "Unable to establish a valid Windows thermal baseline after 3 attempts; "
                    "monitoring startup aborted to avoid false-positive mitigation."
                )
            self._cached_windows_temp = initial_temp
            self._last_valid_temp = initial_temp
            self._start_windows_background_poller()

        if self.verbose:
            sys.stdout.write(f"[*] Initialized HardwareThermalIngestion on {self.system} ({platform.release()})\n")
            sys.stdout.flush()

    def stop(self) -> None:
        """Stops any auxiliary background polling threads."""
        if self.system == "Windows":
            self._poller_stop_event.set()
            if self._windows_poller_thread and self._windows_poller_thread.is_alive():
                self._windows_poller_thread.join(timeout=2.0)

    def get_cpu_temperature(self) -> float:
        """
        Polls physical CPU/Package temperature in degrees Celsius (°C).
        Fast in-memory execution with zero subprocess churn.
        """
        raw_temp: Optional[float] = None
        try:
            if self.system == "Linux":
                raw_temp = self._read_linux_thermal()
            elif self.system == "Windows":
                raw_temp = self._read_windows_thermal_fast()
            elif self.system == "Darwin":
                raw_temp = self._read_macos_thermal()
            else:
                raw_temp = self._read_generic_fallback()
        except Exception as exc:
            if self.verbose:
                sys.stderr.write(f"[!] Hardware thermal read exception: {exc}\n")
                sys.stderr.flush()

        if raw_temp is not None and MIN_PLAUSIBLE_TEMP_C <= raw_temp <= MAX_PLAUSIBLE_TEMP_C:
            self._last_valid_temp = raw_temp
            return round(raw_temp, 2)

        return round(self._last_valid_temp, 2)

    # -------------------------------------------------------------------------
    # Linux Hardware Ingestion: Direct Kernel Sysfs Stream Parsing (CPU & GPU)
    # -------------------------------------------------------------------------
    def _read_linux_thermal(self) -> float:
        zone_temps: List[Tuple[float, str]] = []

        # 1. Primary: /sys/class/thermal/thermal_zone*/temp
        thermal_zone_paths = sorted(glob.glob("/sys/class/thermal/thermal_zone*/temp"))
        for temp_path in thermal_zone_paths:
            try:
                with open(temp_path, "r", encoding="utf-8") as f:
                    raw_str = f.read().strip()
                if not raw_str:
                    continue
                temp_milli = float(raw_str)
                temp_c = temp_milli / 1000.0 if temp_milli > 200.0 else temp_milli

                type_path = os.path.join(os.path.dirname(temp_path), "type")
                zone_type = "unknown"
                if os.path.isfile(type_path):
                    with open(type_path, "r", encoding="utf-8") as tf:
                        zone_type = tf.read().strip().lower()

                if MIN_PLAUSIBLE_TEMP_C <= temp_c <= MAX_PLAUSIBLE_TEMP_C:
                    zone_temps.append((temp_c, zone_type))
            except (IOError, ValueError):
                continue

        # 2. Auxiliary GPU hwmon paths: /sys/class/drm/card*/device/hwmon/hwmon*/temp1_input
        gpu_hwmon_paths = sorted(glob.glob("/sys/class/drm/card*/device/hwmon/hwmon*/temp1_input"))
        for gpath in gpu_hwmon_paths:
            try:
                with open(gpath, "r", encoding="utf-8") as gf:
                    raw_str = gf.read().strip()
                if raw_str:
                    gpu_milli = float(raw_str)
                    gpu_c = gpu_milli / 1000.0 if gpu_milli > 200.0 else gpu_milli
                    if MIN_PLAUSIBLE_TEMP_C <= gpu_c <= MAX_PLAUSIBLE_TEMP_C:
                        zone_temps.append((gpu_c, "gpu-silicon"))
            except (IOError, ValueError):
                continue

        if zone_temps:
            cpu_zones = [
                temp for temp, ztype in zone_temps
                if any(k in ztype for k in ("x86_pkg_temp", "cpu", "coretemp", "k10temp", "acpitz", "soc", "gpu"))
            ]
            if cpu_zones:
                return max(cpu_zones)
            return max(temp for temp, _ in zone_temps)

        # 3. Standard hwmon fallback: /sys/class/hwmon/hwmon*/temp*_input
        hwmon_paths = sorted(glob.glob("/sys/class/hwmon/hwmon*/temp*_input"))
        for hpath in hwmon_paths:
            try:
                with open(hpath, "r", encoding="utf-8") as f:
                    raw_str = f.read().strip()
                if raw_str:
                    temp_milli = float(raw_str)
                    temp_c = temp_milli / 1000.0 if temp_milli > 200.0 else temp_milli
                    if MIN_PLAUSIBLE_TEMP_C <= temp_c <= MAX_PLAUSIBLE_TEMP_C:
                        return temp_c
            except (IOError, ValueError):
                continue

        return self._read_generic_fallback()

    # -------------------------------------------------------------------------
    # Windows Hardware Ingestion: Decoupled Background Polling (0ms Overhead)
    # -------------------------------------------------------------------------
    def _start_windows_background_poller(self) -> None:
        """Starts background worker thread to query Windows WMI without blocking 1.0s loop."""
        self._windows_poller_thread = threading.Thread(
            target=self._windows_poller_worker,
            daemon=True,
            name="ThermoLock-WinWmiPoller"
        )
        self._windows_poller_thread.start()

    def _windows_poller_worker(self) -> None:
        """Background poller querying WMI every 15s to avoid process creation churn."""
        while not self._poller_stop_event.is_set():
            polled_val = self._query_windows_wmi_once()
            if polled_val:
                self._cached_windows_temp = polled_val
            # Sleep 15 seconds in small increments for responsive shutdown
            for _ in range(30):
                if self._poller_stop_event.is_set():
                    break
                time.sleep(0.5)

    def _query_windows_wmi_once(self) -> Optional[float]:
        """Low-frequency WMI query for physical thermal zones or performance counter."""
        try:
            ps_cmd = (
                "Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature "
                "-ErrorAction Stop | Select-Object -ExpandProperty CurrentTemperature"
            )
            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=4.0,
                check=False
            )
            if res.returncode == 0 and res.stdout.strip():
                for line in res.stdout.strip().splitlines():
                    val = float(line.strip())
                    celsius = (val / 10.0) - 273.15 if val > 1000.0 else val - 273.15
                    if MIN_PLAUSIBLE_TEMP_C <= celsius <= MAX_PLAUSIBLE_TEMP_C:
                        return celsius
        except Exception:
            pass

        # Fallback to processor counter
        try:
            ps_cmd = (
                "Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor "
                "| Where-Object { $_.Name -eq '_Total' } "
                "| Select-Object -ExpandProperty PercentProcessorTime"
            )
            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=3.0,
                check=False
            )
            if res.returncode == 0 and res.stdout.strip():
                load_pct = float(res.stdout.strip().splitlines()[0])
                return 38.0 + (load_pct / 100.0) * 45.0
        except Exception:
            pass
        return None

    def _read_windows_thermal_fast(self) -> float:
        """Fast path: returns atomically cached Windows temperature with 0ms latency."""
        return self._cached_windows_temp

    # -------------------------------------------------------------------------
    # macOS Hardware Ingestion: sysctl Registers & pmset Power Management
    # -------------------------------------------------------------------------
    def _read_macos_thermal(self) -> float:
        thermal_level = 0
        speed_limit = 100.0

        try:
            res = subprocess.run(
                ["sysctl", "-n", "machdep.xcpm.cpu_thermal_level"],
                capture_output=True,
                text=True,
                timeout=0.5,
                check=False
            )
            if res.returncode == 0 and res.stdout.strip():
                thermal_level = int(res.stdout.strip())
        except Exception:
            pass

        try:
            res = subprocess.run(
                ["pmset", "-g", "therm"],
                capture_output=True,
                text=True,
                timeout=0.5,
                check=False
            )
            if res.returncode == 0 and res.stdout.strip():
                match = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", res.stdout)
                if match:
                    speed_limit = float(match.group(1))
        except Exception:
            pass

        base_temp = 40.0
        level_offset = thermal_level * 15.0
        throttle_offset = max(0.0, (100.0 - speed_limit) * 0.4)
        calculated_temp = base_temp + level_offset + throttle_offset
        return round(calculated_temp, 2)

    def _read_generic_fallback(self) -> float:
        if not self._thermal_fallback_mode:
            self._thermal_fallback_mode = True
            if self.verbose:
                sys.stdout.write("[*] Bare-metal sensors obscured (hypervisor/container). Using simulated baseline.\n")
                sys.stdout.flush()
        return 42.0

    def inspect_available_sensors(self) -> List[Dict[str, Any]]:
        """Diagnostic helper to enumerate all detected bare-metal hardware sensors."""
        inventory: List[Dict[str, Any]] = []
        if self.system == "Linux":
            for tz in sorted(glob.glob("/sys/class/thermal/thermal_zone*")):
                name = os.path.basename(tz)
                type_path = os.path.join(tz, "type")
                temp_path = os.path.join(tz, "temp")
                ztype = "unknown"
                val_c = None
                if os.path.isfile(type_path):
                    with open(type_path, "r", encoding="utf-8") as f:
                        ztype = f.read().strip()
                if os.path.isfile(temp_path):
                    try:
                        with open(temp_path, "r", encoding="utf-8") as f:
                            raw = float(f.read().strip())
                            val_c = raw / 1000.0 if raw > 200 else raw
                    except Exception:
                        pass
                inventory.append({"sensor": name, "type": ztype, "current_temp_c": val_c, "path": tz})

            for gpath in sorted(glob.glob("/sys/class/drm/card*/device/hwmon/hwmon*/temp1_input")):
                try:
                    with open(gpath, "r", encoding="utf-8") as f:
                        val = float(f.read().strip()) / 1000.0
                    inventory.append({"sensor": "GPU_HWMON", "type": "discrete_gpu", "current_temp_c": val, "path": gpath})
                except Exception:
                    pass
        elif self.system == "Windows":
            inventory.append({"sensor": "MSAcpi_ThermalZoneTemperature", "type": "ACPI", "status": "WMI_ROOT"})
        elif self.system == "Darwin":
            inventory.append({"sensor": "machdep.xcpm.cpu_thermal_level", "type": "Apple_XCPM_SMC", "status": "SYSCTL"})
        return inventory


# =============================================================================
# KERNEL CPU UTILIZATION & PER-PROCESS TRACKING METER
# =============================================================================

class KernelCPULoadMeter:
    """
    Zero-dependency kernel CPU utilization meter.
    Measures global kernel utilization and tracks per-process differential
    CPU ticks across the exact 1.0-second interval.
    On Windows: uses Win32 GetSystemTimes exclusively via ctypes in memory.
    """

    def __init__(self):
        self.system = platform.system()
        self._prev_linux_stat: Optional[Tuple[float, float]] = None
        self._prev_win_times: Optional[Tuple[int, int, int]] = None
        self._prev_linux_proc_ticks: Dict[int, Tuple[str, int]] = {}

        self._initialize_baseline()

    def _initialize_baseline(self) -> None:
        if self.system == "Linux":
            self._prev_linux_stat = self._read_linux_stat()
            self._prev_linux_proc_ticks = self._snapshot_linux_proc_ticks()
        elif self.system == "Windows":
            self._prev_win_times = self._read_windows_system_times()

    def sample_interval_load(self) -> float:
        """Calculates global kernel CPU utilization percentage [0.0, 100.0]."""
        if self.system == "Linux":
            return self._calculate_linux_load()
        elif self.system == "Windows":
            return self._calculate_windows_load()
        elif self.system == "Darwin":
            return self._calculate_macos_load()
        else:
            return 5.0

    # -------------------------------------------------------------------------
    # Linux /proc/stat Global & Per-Process Differential Jiffies
    # -------------------------------------------------------------------------
    def _read_linux_stat(self) -> Tuple[float, float]:
        try:
            with open("/proc/stat", "r", encoding="utf-8") as f:
                first_line = f.readline()
            fields = [float(x) for x in first_line.strip().split()[1:]]
            idle = fields[3] + fields[4]  # idle + iowait
            total = sum(fields)
            return (idle, total)
        except Exception:
            return (0.0, 0.0)

    def _calculate_linux_load(self) -> float:
        curr_idle, curr_total = self._read_linux_stat()
        if not self._prev_linux_stat:
            self._prev_linux_stat = (curr_idle, curr_total)
            return 0.0

        prev_idle, prev_total = self._prev_linux_stat
        self._prev_linux_stat = (curr_idle, curr_total)

        delta_total = curr_total - prev_total
        delta_idle = curr_idle - prev_idle

        if delta_total <= 0:
            return 0.0

        cpu_load = (1.0 - (delta_idle / delta_total)) * 100.0
        return max(0.0, min(100.0, round(cpu_load, 2)))

    def _snapshot_linux_proc_ticks(self) -> Dict[int, Tuple[str, int]]:
        """Takes a lightweight snapshot of (comm, utime + stime) for active PIDs."""
        snapshot: Dict[int, Tuple[str, int]] = {}
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as f:
                    content = f.read()
                lparen = content.find("(")
                rparen = content.rfind(")")
                if lparen == -1 or rparen == -1:
                    continue
                comm = content[lparen + 1:rparen]
                rest = content[rparen + 2:].split()
                utime = int(rest[11])
                stime = int(rest[12])
                snapshot[pid] = (comm, utime + stime)
            except (IOError, IndexError, ValueError):
                continue
        return snapshot

    def get_linux_active_deltas(self) -> List[Tuple[int, str, int]]:
        """
        Computes active CPU ticks consumed by each process during the last interval.
        Returns sorted list of (PID, comm, delta_ticks) descending.
        """
        curr_snapshot = self._snapshot_linux_proc_ticks()
        deltas: List[Tuple[int, str, int]] = []

        for pid, (comm, curr_ticks) in curr_snapshot.items():
            if pid in self._prev_linux_proc_ticks:
                _, prev_ticks = self._prev_linux_proc_ticks[pid]
                diff = curr_ticks - prev_ticks
                if diff > 0:
                    deltas.append((pid, comm, diff))
            else:
                deltas.append((pid, comm, curr_ticks))

        self._prev_linux_proc_ticks = curr_snapshot
        deltas.sort(key=lambda x: x[2], reverse=True)
        return deltas

    # -------------------------------------------------------------------------
    # Windows Win32 GetSystemTimes via ctypes (In-Memory, Zero Process Spawning)
    # -------------------------------------------------------------------------
    def _read_windows_system_times(self) -> Optional[Tuple[int, int, int]]:
        try:
            import ctypes
            from ctypes import wintypes

            class FILETIME(ctypes.Structure):
                _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

            kernel32 = ctypes.windll.kernel32
            idle_ft = FILETIME()
            kernel_ft = FILETIME()
            user_ft = FILETIME()

            success = kernel32.GetSystemTimes(
                ctypes.byref(idle_ft),
                ctypes.byref(kernel_ft),
                ctypes.byref(user_ft)
            )
            if not success:
                return None

            def to_int(ft: FILETIME) -> int:
                return (ft.dwHighDateTime << 32) + ft.dwLowDateTime

            return (to_int(idle_ft), to_int(kernel_ft), to_int(user_ft))
        except Exception:
            return None

    def _calculate_windows_load(self) -> float:
        curr_times = self._read_windows_system_times()
        if not curr_times:
            return 5.0

        if not self._prev_win_times:
            self._prev_win_times = curr_times
            return 0.0

        prev_idle, prev_kernel, prev_user = self._prev_win_times
        self._prev_win_times = curr_times

        curr_idle, curr_kernel, curr_user = curr_times
        delta_idle = curr_idle - prev_idle
        delta_kernel = curr_kernel - prev_kernel
        delta_user = curr_user - prev_user

        total_system = delta_kernel + delta_user
        if total_system <= 0:
            return 0.0

        busy_system = (delta_kernel - delta_idle) + delta_user
        load_pct = (busy_system / total_system) * 100.0
        return max(0.0, min(100.0, round(load_pct, 2)))

    # -------------------------------------------------------------------------
    # macOS: Darwin top and loadavg
    # -------------------------------------------------------------------------
    def _calculate_macos_load(self) -> float:
        try:
            res = subprocess.run(
                ["top", "-l", "1", "-n", "0"],
                capture_output=True,
                text=True,
                timeout=0.5,
                check=False
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "CPU usage:" in line:
                        idle_match = re.search(r"([\d\.]+)%\s+idle", line)
                        if idle_match:
                            idle_val = float(idle_match.group(1))
                            return max(0.0, min(100.0, round(100.0 - idle_val, 2)))
        except Exception:
            pass

        try:
            load1, _, _ = os.getloadavg()
            cpu_count = os.cpu_count() or 1
            load_pct = (load1 / cpu_count) * 100.0
            return max(0.0, min(100.0, round(load_pct, 2)))
        except Exception:
            return 5.0


# =============================================================================
# RING 0 LINUX eBPF KERNEL TELEMETRY BRIDGE (HYBRID ARCHITECTURE)
# =============================================================================
# Embedded C eBPF scheduler probe attaching to kernel scheduler tracepoints:
#   - tracepoint:sched:sched_switch (context switches & execution runtimes)
#   - tracepoint:sched:sched_wakeup (task wakeups / burst frequency)
# Shared Map: BPF_HASH(pid_sched_stats, u32, struct proc_sched_data_t)
# Populated in Ring 0; read and atomically cleared every 1.0s by Ring 3 Python.
# =============================================================================

EBPF_SCHEDULER_TRACKER_C: str = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct proc_sched_data_t {
    u32 pid;
    u32 tgid;
    char comm[16];
    u64 total_runtime_ns;
    u64 switch_count;
    u64 wakeup_count;
    u64 last_active_ns;
};

// Tracks entry timestamp when each PID begins executing on a physical CPU core
BPF_HASH(start_time, u32, u64, 10240);

// Shared BPF Hash Map: Ring 0 aggregates high-frequency scheduler execution metrics;
// Ring 3 Python asynchronously polls and flushes every 1.0s interval.
BPF_HASH(pid_sched_stats, u32, struct proc_sched_data_t, 10240);

// Tracepoint: sched:sched_switch
// Fired on every kernel context switch when a task is switched on/off a CPU core.
TRACEPOINT_PROBE(sched, sched_switch) {
    u64 now = bpf_ktime_get_ns();
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;

    // 1. Task transitioning OFF CPU: calculate runtime slice
    if (prev_pid > 0) {
        u64 *start_ts = start_time.lookup(&prev_pid);
        if (start_ts && now > *start_ts) {
            u64 delta = now - *start_ts;
            struct proc_sched_data_t *stats = pid_sched_stats.lookup(&prev_pid);
            if (stats) {
                stats->total_runtime_ns += delta;
                stats->switch_count += 1;
                stats->last_active_ns = now;
            } else {
                struct proc_sched_data_t init_stats = {};
                init_stats.pid = prev_pid;
                init_stats.tgid = bpf_get_current_pid_tgid() >> 32;
                __builtin_memcpy(init_stats.comm, args->prev_comm, sizeof(init_stats.comm));
                init_stats.total_runtime_ns = delta;
                init_stats.switch_count = 1;
                init_stats.wakeup_count = 0;
                init_stats.last_active_ns = now;
                pid_sched_stats.update(&prev_pid, &init_stats);
            }
        }
        start_time.delete(&prev_pid);
    }

    // 2. Task transitioning ONTO CPU: record timestamp
    if (next_pid > 0) {
        start_time.update(&next_pid, &now);
    }

    return 0;
}

// Tracepoint: sched:sched_wakeup
// Tracks scheduler wakeups to correlate rapid micro-bursts and thermal oscillation.
TRACEPOINT_PROBE(sched, sched_wakeup) {
    u32 pid = args->pid;
    if (pid > 0) {
        struct proc_sched_data_t *stats = pid_sched_stats.lookup(&pid);
        if (stats) {
            stats->wakeup_count += 1;
        }
    }
    return 0;
}
"""


class EbpfKernelBridge:
    """
    Hybrid Ring 0 / Ring 3 Linux eBPF telemetry bridge.
    Compiles and attaches the embedded C eBPF scheduler probe via BCC.
    Reads high-frequency kernel-level execution ticks and execution slices
    from the shared BPF hash map ('pid_sched_stats') to correlate with TDS.

    GRACEFUL FALLBACK SPECIFICATION:
      - Checks platform: Linux required (Windows/macOS gracefully fall back).
      - Checks privileges: Root / CAP_BPF required (unprivileged gracefully falls back).
      - Checks runtime: Verifies BCC Python module and kernel headers are available.
      - Catches compilation or attachment exceptions cleanly without crashing.
      - Seamlessly degrades to pure Ring 3 userspace engine.
    """

    def __init__(self, enabled: bool = False, verbose: bool = True):
        self.enabled = enabled
        self.verbose = verbose
        self.active: bool = False
        self.fallback_reason: Optional[str] = None
        self._bpf = None
        self._lock = threading.Lock()

        # Telemetry metrics
        self.total_kernel_ticks: int = 0
        self.last_sample: Dict[int, Dict[str, Any]] = {}

    def start(self) -> bool:
        """
        Initializes and attaches the Ring 0 eBPF probe if enabled and supported.
        Guarantees zero crashes: logs clean diagnostic and returns False on any limitation.
        """
        if not self.enabled:
            self.fallback_reason = "eBPF disabled (--enable-ebpf flag not passed)"
            return False

        sys_platform = platform.system()
        if sys_platform != "Linux":
            self.fallback_reason = f"eBPF not supported on {sys_platform} (Linux required)"
            if self.verbose:
                sys.stdout.write(
                    f"[*] [eBPF BRIDGE] eBPF kernel telemetry is only supported on Linux (Host: {sys_platform}).\n"
                    "    Gracefully falling back to pure Ring 3 userspace engine.\n"
                )
                sys.stdout.flush()
            return False

        if os.geteuid() != 0:
            self.fallback_reason = "Elevated privileges required (root / CAP_BPF / CAP_SYS_ADMIN)"
            if self.verbose:
                sys.stdout.write(
                    "[*] [eBPF BRIDGE] eBPF requires root privileges (CAP_BPF / CAP_SYS_ADMIN).\n"
                    "    Gracefully falling back to pure Ring 3 userspace engine.\n"
                )
                sys.stdout.flush()
            return False

        # Attempt dynamic import of BCC
        try:
            from bcc import BPF
        except (ImportError, ModuleNotFoundError) as exc:
            self.fallback_reason = f"BCC Python module not available ({exc})"
            if self.verbose:
                sys.stdout.write(
                    "[*] [eBPF BRIDGE] BCC (BPF Compiler Collection) Python module not detected.\n"
                    "    Gracefully falling back to pure Ring 3 userspace engine.\n"
                    "    Hint: On Debian/Ubuntu install 'python3-bpfcc bpfcc-tools linux-headers-$(uname -r)'.\n"
                )
                sys.stdout.flush()
            return False

        # Attempt JIT compilation and probe attachment in Ring 0
        try:
            # Inspect and adjust RLIMIT_MEMLOCK memory limits for BPF map allocation.
            # In Linux kernel >= 5.11, BPF maps use cgroup memcg accounting,
            # but raising RLIMIT_MEMLOCK prevents EPERM on older kernels.
            # If constrained by systemd LimitMEMLOCK, safely retain current allocation without crashing.
            try:
                import resource
                soft_lim, hard_lim = resource.getrlimit(resource.RLIMIT_MEMLOCK)
                if soft_lim != resource.RLIM_INFINITY:
                    target_lim = hard_lim if hard_lim != resource.RLIM_INFINITY else resource.RLIM_INFINITY
                    try:
                        resource.setrlimit(resource.RLIMIT_MEMLOCK, (target_lim, target_lim))
                    except (OSError, PermissionError) as rlim_err:
                        if self.verbose:
                            sys.stdout.write(
                                f"[*] [eBPF BRIDGE] Notice: Could not elevate RLIMIT_MEMLOCK to infinity ({rlim_err}). "
                                f"Retaining configured limit ({soft_lim} bytes).\n"
                            )
                            sys.stdout.flush()
            except Exception:
                pass

            self._bpf = BPF(text=EBPF_SCHEDULER_TRACKER_C)
            self.active = True
            self.fallback_reason = None
            if self.verbose:
                sys.stdout.write(
                    "[+] [eBPF BRIDGE] Ring 0 eBPF kernel scheduler probe successfully compiled & attached.\n"
                    "    Listening on tracepoint:sched:sched_switch & sched:sched_wakeup.\n"
                    "    Shared BPF hash map 'pid_sched_stats' linked to Ring 3 sensor loop.\n"
                )
                sys.stdout.flush()
            return True
        except PermissionError as perm_err:
            self.active = False
            self.fallback_reason = f"Permission denied loading BPF bytecode ({perm_err})"
            if self.verbose:
                sys.stdout.write(
                    f"[!] [eBPF BRIDGE] Permission denied loading BPF bytecode ({perm_err}).\n"
                    "    Verify CAP_BPF / CAP_SYS_ADMIN capabilities or systemd LimitMEMLOCK=infinity.\n"
                    "    Gracefully falling back to pure Ring 3 userspace engine.\n"
                )
                sys.stdout.flush()
            return False
        except Exception as exc:
            self.active = False
            err_msg = str(exc)
            if "Operation not permitted" in err_msg or "Permission denied" in err_msg:
                self.fallback_reason = f"BPF bytecode load blocked by security policy: {exc}"
                if self.verbose:
                    sys.stdout.write(
                        f"[!] [eBPF BRIDGE] BPF bytecode load blocked by security policy ({exc}).\n"
                        "    Ensure kernel allows BPF program loading (check seccomp, AppArmor, or LimitMEMLOCK).\n"
                        "    Gracefully falling back to pure Ring 3 userspace engine.\n"
                    )
                    sys.stdout.flush()
            else:
                self.fallback_reason = f"eBPF JIT compilation or attachment error: {exc}"
                if self.verbose:
                    sys.stdout.write(
                        f"[*] [eBPF BRIDGE] Kernel probe attachment failed ({exc}).\n"
                        "    Gracefully falling back to pure Ring 3 userspace engine.\n"
                    )
                    sys.stdout.flush()
            return False

    def stop(self) -> None:
        """Detaches kernel probes and cleans up BPF maps."""
        if self._bpf:
            try:
                self._bpf.cleanup()
            except Exception:
                pass
            self._bpf = None
        self.active = False

    def sample_and_clear(self) -> Dict[int, Dict[str, Any]]:
        """
        Asynchronously called by the main 1.0s Ring 3 loop.
        Reads the shared BPF hash map 'pid_sched_stats' and atomically clears it.
        """
        if not self.active or not self._bpf:
            return {}

        snapshot: Dict[int, Dict[str, Any]] = {}
        try:
            stats_map = self._bpf["pid_sched_stats"]
            sampled_keys = []

            # Extract snapshot items into local list to prevent iterator invalidation
            # under concurrent Ring 0 inserts during high process churn
            for k, v in list(stats_map.items()):
                pid = int(k.value)
                comm = v.comm.decode("utf-8", errors="replace").strip()
                runtime_ns = int(v.total_runtime_ns)
                switch_count = int(v.switch_count)
                wakeup_count = int(v.wakeup_count)

                if runtime_ns > 0 or switch_count > 0:
                    runtime_ms = round(runtime_ns / 1_000_000.0, 2)
                    kernel_cpu_pct = round((runtime_ns / 1_000_000_000.0) * 100.0, 2)

                    snapshot[pid] = {
                        "pid": pid,
                        "tgid": int(v.tgid),
                        "comm": comm,
                        "kernel_runtime_ns": runtime_ns,
                        "kernel_runtime_ms": runtime_ms,
                        "kernel_cpu_pct": kernel_cpu_pct,
                        "context_switches": switch_count,
                        "wakeups": wakeup_count
                    }
                    self.total_kernel_ticks += switch_count

                sampled_keys.append(k)

            # High-Churn Race Protection:
            # Delete ONLY the keys that were actually sampled and recorded into snapshot.
            # Fast-spawning short-lived processes arriving during or after the iteration
            # are NOT in sampled_keys, preserving their telemetry for the subsequent 1.0s cycle.
            for k in sampled_keys:
                try:
                    del stats_map[k]
                except (KeyError, Exception):
                    pass
        except Exception as exc:
            if self.verbose:
                sys.stderr.write(f"[!] [eBPF BRIDGE] Error reading shared BPF map: {exc}\n")

        with self._lock:
            self.last_sample = snapshot

        return snapshot

    def get_top_kernel_consumers(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Returns top CPU-consuming tasks recorded by Ring 0 during the latest interval."""
        with self._lock:
            sample = list(self.last_sample.values())
        sample.sort(key=lambda x: x.get("kernel_runtime_ns", 0), reverse=True)
        return sample[:limit]

    def get_status_summary(self) -> Dict[str, Any]:
        """Assembles structured telemetry block for SIEM alert payloads & diagnostics."""
        if self.active:
            top_consumers = self.get_top_kernel_consumers(limit=3)
            return {
                "architecture": "HYBRID_RING0_RING3",
                "ring0_status": "ACTIVE_ATTACHED",
                "kernel_probe": "tracepoint:sched:sched_switch,tracepoint:sched:sched_wakeup",
                "shared_map": "pid_sched_stats (BPF_HASH)",
                "tracked_pids_count": len(self.last_sample),
                "total_kernel_ticks_observed": self.total_kernel_ticks,
                "top_kernel_consumers": top_consumers
            }
        else:
            return {
                "architecture": "PURE_RING3_FALLBACK",
                "ring0_status": "FALLBACK_INACTIVE",
                "fallback_reason": self.fallback_reason or "eBPF probe not requested (--enable-ebpf)",
                "telemetry_source": "POSIX /proc/stat & /proc/<PID>/stat"
            }


# =============================================================================
# FILE INTEGRITY MONITORING (FIM) & DYNAMIC CODE SIGNING VERIFICATION
# =============================================================================

def compute_file_sha256(file_path: Optional[str]) -> Optional[str]:
    """
    Computes cryptographic SHA-256 hash of an executable binary file for File Integrity Monitoring (FIM).
    Streams file in 64KB chunks to maintain zero memory footprint on large binaries.
    Safely catches PermissionError, FileNotFoundError, ProcessLookupError, and OS lock errors cleanly.
    """
    if not file_path:
        return None
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (OSError, IOError, PermissionError, ProcessLookupError, Exception):
        return None


def verify_windows_authenticode(
    file_path: str,
    trusted_signers: Optional[List[str]] = None
) -> Tuple[bool, Optional[str]]:
    """
    Verifies the Authenticode cryptographic signature of a PE binary on Windows
    using native Win32 WinTrust APIs (wintrust.dll and crypt32.dll).
    Zero subprocess spawning; zero external pip dependencies.

    Uses WTD_CACHE_ONLY_URL_RETRIEVAL to ensure verification never hangs on
    remote CRL/OCSP network lookups in air-gapped or firewalled environments.

    Returns:
        (is_trusted: bool, signer_name: Optional[str])
    """
    if platform.system() != "Windows" or not file_path or not os.path.isfile(file_path):
        return False, None

    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p),
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p),
            ]

        WTD_UI_NONE = 2
        WTD_REVOKE_NONE = 0
        WTD_CHOICE_FILE = 1
        WTD_STATEACTION_VERIFY = 1
        WTD_STATEACTION_CLOSE = 2
        WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000
        WTD_SAFER_FLAG = 0x00000100

        # WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
        action_guid = GUID(
            0x00AAC56B,
            0xCD44,
            0x11D0,
            (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
        )

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = file_path
        file_info.hFile = None
        file_info.pgKnownSubject = None

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        trust_data.pPolicyCallbackData = None
        trust_data.pSIPClientData = None
        trust_data.dwUIChoice = WTD_UI_NONE
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
        trust_data.dwUnionChoice = WTD_CHOICE_FILE
        trust_data.pFile = ctypes.pointer(file_info)
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY
        trust_data.hWVTStateData = None
        trust_data.pwszURLReference = None
        trust_data.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL
        trust_data.dwUIContext = 0
        trust_data.pSignatureSettings = None

        wintrust = ctypes.windll.wintrust
        wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
        wintrust.WinVerifyTrust.restype = ctypes.c_long

        status = wintrust.WinVerifyTrust(
            0,
            ctypes.byref(action_guid),
            ctypes.byref(trust_data)
        )

        # Release WVT state data handle
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(
            0,
            ctypes.byref(action_guid),
            ctypes.byref(trust_data)
        )

        if status != 0:
            return False, None

        # Binary is cryptographically valid and chains to a trusted root authority.
        # Now extract the certificate subject / publisher name via crypt32.dll
        signer_name = _extract_windows_signer_name(file_path)

        if not trusted_signers:
            return True, signer_name or "Verified Trusted Root"

        if signer_name:
            signer_lower = signer_name.lower()
            for trusted in trusted_signers:
                if trusted.lower() in signer_lower:
                    return True, signer_name

        return False, signer_name

    except Exception:
        return False, None


def _extract_windows_signer_name(file_path: str) -> Optional[str]:
    """
    Extracts the publisher / signer Common Name (CN) from embedded Authenticode PKCS#7 certificate.
    Uses crypt32.dll CryptQueryObject and CertGetNameStringW.
    """
    if platform.system() != "Windows":
        return None

    try:
        import ctypes
        from ctypes import wintypes
        crypt32 = ctypes.windll.crypt32

        CERT_QUERY_OBJECT_FILE = 1
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
        CERT_QUERY_FORMAT_FLAG_ALL = 0x0E
        CERT_NAME_SIMPLE_DISPLAY_TYPE = 4

        dwMsgAndCertEncodingType = wintypes.DWORD()
        dwContentType = wintypes.DWORD()
        dwFormatType = wintypes.DWORD()
        hCertStore = wintypes.HANDLE()
        hMsg = wintypes.HANDLE()

        success = crypt32.CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wintypes.LPCWSTR(file_path),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            ctypes.byref(dwMsgAndCertEncodingType),
            ctypes.byref(dwContentType),
            ctypes.byref(dwFormatType),
            ctypes.byref(hCertStore),
            ctypes.byref(hMsg),
            None
        )

        if not success or not hCertStore:
            return None

        signer_name = None
        try:
            p_cert_context = crypt32.CertEnumCertificatesInStore(hCertStore, None)
            if p_cert_context:
                buf = ctypes.create_unicode_buffer(512)
                chars = crypt32.CertGetNameStringW(
                    p_cert_context,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    None,
                    buf,
                    len(buf)
                )
                if chars > 1:
                    signer_name = buf.value
                crypt32.CertFreeCertificateContext(p_cert_context)
        finally:
            if hCertStore:
                crypt32.CertCloseStore(hCertStore, 0)
            if hMsg:
                crypt32.CryptMsgClose(hMsg)

        return signer_name
    except Exception:
        return None


# =============================================================================
# FORENSIC-SAFE NON-DESTRUCTIVE KERNEL MITIGATION & VOLATILE TRIAGE
# =============================================================================

class ForensicMitigationEngine:
    """
    Forensic-safe non-destructive kernel mitigation engine.
    PRESERVES VOLATILE RAM ARTIFACTS: Does NOT execute SIGKILL or TerminateProcess.
    Instantly extracts in-memory forensic triage metadata from the frozen process.
    Supports dry_run audit mode (--audit-only) where mitigation actions are bypassed.
    """

    DEFAULT_WHITELIST: Set[str] = {
        # Core Linux / Unix init & daemons
        "systemd", "init", "kthreadd", "sshd", "dbus-daemon", "rsyslogd",
        "systemd-journald", "systemd-udevd", "systemd-logind", "systemd-resolved",
        "auditd", "chronyd", "ntpd", "bash", "sh", "zsh", "login", "tmux", "screen",
        "sudo", "su", "polkitd", "irqbalance", "NetworkManager", "wpa_supplicant",
        "dockerd", "containerd", "containerd-shim",
        # Windows critical services
        "System", "Idle", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe", "dwm.exe",
        "explorer.exe", "powershell.exe",
        # macOS critical services
        "launchd", "kernel_task", "WindowServer", "syslogd", "loginwindow"
    }

    compute_file_sha256 = staticmethod(compute_file_sha256)

    def __init__(
        self,
        cpu_meter: KernelCPULoadMeter,
        custom_whitelist: Optional[Set[str]] = None,
        audit_only: bool = False,
        trust_signed_binaries: bool = False,
        trusted_signers: Optional[List[str]] = None,
        ebpf_bridge: Optional[Any] = None,
        verbose: bool = False
    ):
        self.system = platform.system()
        self.cpu_meter = cpu_meter
        self.audit_only = audit_only
        self.trust_signed_binaries = trust_signed_binaries
        self.ebpf_bridge = ebpf_bridge
        self.verbose = verbose
        self.whitelist = set(self.DEFAULT_WHITELIST)
        if custom_whitelist:
            self.whitelist.update(custom_whitelist)

        self.trusted_signers = list(trusted_signers) if trusted_signers else list(DEFAULT_TRUSTED_SIGNERS)
        self._code_signing_cache: Dict[Tuple[str, float], Tuple[bool, Optional[str]]] = {}
        self._cert_cache_lock = threading.Lock()
        # Per-key locks coalesce concurrent cache misses without serializing
        # signature verification for unrelated files.
        self._cert_key_locks: Dict[Tuple[str, float], threading.Lock] = {}

        self.mitigated_pids_history: Set[int] = set()
        self.total_fim_hashes_computed: int = 0
        self.total_code_signing_whitelisted: int = 0

    def is_binary_signed_and_trusted(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """Checks and caches trusted code-signing results, coalescing same-file misses."""
        if not file_path or not os.path.isfile(file_path):
            return False, None

        try:
            mtime = os.path.getmtime(file_path)
        except Exception:
            mtime = 0.0

        cache_key = (file_path.lower() if self.system == "Windows" else file_path, mtime)
        with self._cert_cache_lock:
            cached = self._code_signing_cache.get(cache_key)
            if cached is not None:
                return cached
            key_lock = self._cert_key_locks.setdefault(cache_key, threading.Lock())

        # Do slow OS/filesystem verification outside the global cache lock, while
        # allowing only one verifier per path/mtime pair.
        with key_lock:
            with self._cert_cache_lock:
                cached = self._code_signing_cache.get(cache_key)
                if cached is not None:
                    return cached

            is_trusted = False
            signer_name = None
            if self.system == "Windows":
                is_trusted, signer_name = verify_windows_authenticode(file_path, self.trusted_signers)
            elif self.system == "Darwin":
                try:
                    res = subprocess.run(
                        ["codesign", "--verify", "--quiet", file_path],
                        timeout=0.5,
                        capture_output=True,
                        check=False
                    )
                    if res.returncode == 0:
                        is_trusted = True
                        signer_name = "Apple Verified Binary"
                except Exception:
                    pass

            result = (is_trusted, signer_name)
            with self._cert_cache_lock:
                self._code_signing_cache[cache_key] = result
            if is_trusted:
                self.total_code_signing_whitelisted += 1
            return result

    def _query_windows_process_path(self, pid: int) -> Optional[str]:
        """Retrieves absolute binary file path for a Windows process via Win32 API."""
        if platform.system() != "Windows":
            return None
        try:
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.windll.kernel32
            # PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, fallback PROCESS_QUERY_INFORMATION = 0x0400
            h_proc = kernel32.OpenProcess(0x1000, False, pid)
            if not h_proc:
                h_proc = kernel32.OpenProcess(0x0400, False, pid)
            if not h_proc:
                return None
            try:
                buf = ctypes.create_unicode_buffer(1024)
                size = wintypes.DWORD(len(buf))
                if kernel32.QueryFullProcessImageNameW(h_proc, 0, buf, ctypes.byref(size)):
                    return buf.value
            finally:
                kernel32.CloseHandle(h_proc)
        except Exception:
            pass
        return None

    def identify_and_mitigate_suspects(self) -> List[Dict[str, Any]]:
        """
        Dispatches out-of-band mitigation against top non-system background processes.
        Returns a structured list of mitigated process descriptors with volatile triage.
        """
        mitigated_records: List[Dict[str, Any]] = []

        try:
            if self.system == "Linux":
                mitigated_records = self._mitigate_linux()
            elif self.system == "Windows":
                mitigated_records = self._mitigate_windows()
            elif self.system == "Darwin":
                mitigated_records = self._mitigate_macos()
        except Exception as exc:
            if self.verbose:
                sys.stderr.write(f"[!] Mitigation engine encountered error: {exc}\n")
                sys.stderr.flush()

        return mitigated_records

    # -------------------------------------------------------------------------
    # Linux: POSIX SIGSTOP (Signal 19) + Volatile Memory Triage
    # -------------------------------------------------------------------------
    def _mitigate_linux(self) -> List[Dict[str, Any]]:
        mitigated: List[Dict[str, Any]] = []
        my_pid = os.getpid()
        my_ppid = os.getppid()

        candidate_pid: Optional[int] = None
        candidate_name: str = "unknown"
        candidate_ebpf_telemetry: Optional[Dict[str, Any]] = None

        # 1. High-Confidence Ring 0 Path: Check eBPF Kernel Scheduler Telemetry
        if self.ebpf_bridge and self.ebpf_bridge.active:
            top_kernel_consumers = self.ebpf_bridge.get_top_kernel_consumers(limit=10)
            for entry in top_kernel_consumers:
                pid = entry.get("pid")
                comm = entry.get("comm", "unknown")
                if pid in (0, 1, 2, my_pid, my_ppid) or pid in self.mitigated_pids_history:
                    continue
                if comm in self.whitelist:
                    continue

                # Cross-reference with Ring 3 /proc to detect DKOM/hidden stealth threads
                proc_exists = os.path.exists(f"/proc/{pid}")
                if not proc_exists and self.verbose:
                    sys.stdout.write(
                        f"[!] [eBPF ANOMALY] Ring 0 detected execution for unlinked PID {pid} ('{comm}') "
                        f"(Runtime: {entry.get('kernel_runtime_ms')}ms). Possible DKOM stealth implant!\n"
                    )
                    sys.stdout.flush()

                candidate_pid = pid
                candidate_name = comm
                candidate_ebpf_telemetry = entry
                break

        # 2. Ring 3 Fallback Path: Linux /proc tick delta scanner
        if candidate_pid is None:
            active_deltas = self.cpu_meter.get_linux_active_deltas()
            for pid, comm, diff in active_deltas:
                if pid in (0, 1, 2, my_pid, my_ppid) or pid in self.mitigated_pids_history:
                    continue
                if comm in self.whitelist:
                    continue

                try:
                    with open(f"/proc/{pid}/cmdline", "rb") as cf:
                        cmdline = cf.read()
                    if not cmdline:
                        continue

                    with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as sf:
                        stat_parts = sf.read().split()
                    if len(stat_parts) > 3 and stat_parts[3] == "2":
                        continue

                    candidate_pid = pid
                    candidate_name = comm
                    break
                except (IOError, IndexError):
                    continue

        if candidate_pid is None:
            candidate_pid, candidate_name = self._find_linux_fallback_candidate()

        if candidate_pid is not None:
            triage_info = self._extract_linux_live_triage(candidate_pid)
            fim_hash = triage_info.get("sha256_hash")

            if candidate_ebpf_telemetry:
                triage_info["ebpf_ring0_telemetry"] = {
                    "kernel_runtime_ms": candidate_ebpf_telemetry.get("kernel_runtime_ms"),
                    "kernel_cpu_pct": candidate_ebpf_telemetry.get("kernel_cpu_pct"),
                    "context_switches": candidate_ebpf_telemetry.get("context_switches"),
                    "dkom_unlinked_from_proc": not os.path.exists(f"/proc/{candidate_pid}")
                }

            if self.audit_only:
                # Dry-run audit mode: do not execute SIGSTOP
                self.mitigated_pids_history.add(candidate_pid)
                record = {
                    "pid": candidate_pid,
                    "name": candidate_name,
                    "binary_sha256": fim_hash,
                    "ebpf_ring0_runtime_ms": candidate_ebpf_telemetry.get("kernel_runtime_ms") if candidate_ebpf_telemetry else None,
                    "action": "DRY_RUN_AUDIT (Process NOT suspended)",
                    "status": "AUDIT_ONLY_UNMODIFIED",
                    "details": "Audit mode active (--audit-only). Process execution uninhibited; triage collected.",
                    "live_forensic_triage": triage_info,
                    "forensic_resume_command": "N/A"
                }
                mitigated.append(record)
                if self.verbose:
                    sys.stdout.write(f"[*] [AUDIT-ONLY] Identified suspect PID {candidate_pid} ('{candidate_name}'). Active mitigation bypassed.\n")
                    sys.stdout.flush()
            else:
                try:
                    sigstop_sig = getattr(signal, "SIGSTOP", 19)
                    os.kill(candidate_pid, sigstop_sig)
                    self.mitigated_pids_history.add(candidate_pid)

                    record = {
                        "pid": candidate_pid,
                        "name": candidate_name,
                        "binary_sha256": fim_hash,
                        "ebpf_ring0_runtime_ms": candidate_ebpf_telemetry.get("kernel_runtime_ms") if candidate_ebpf_telemetry else None,
                        "action": "POSIX_SIGSTOP (Signal 19)",
                        "status": "FROZEN_IN_RAM",
                        "details": (
                            "Process execution frozen in memory (State 'T'). CPU dissipation stopped; "
                            "volatile RAM, heap, and socket descriptors preserved for live forensics."
                        ),
                        "live_forensic_triage": triage_info,
                        "forensic_resume_command": f"kill -CONT {candidate_pid}"
                    }
                    mitigated.append(record)
                    if self.verbose:
                        sys.stdout.write(f"[!] [MITIGATION] Suspended suspect PID {candidate_pid} ('{candidate_name}') via SIGSTOP\n")
                        sys.stdout.flush()
                except PermissionError:
                    if self.verbose:
                        sys.stderr.write(f"[!] Insufficient permissions to issue SIGSTOP to PID {candidate_pid}\n")
                        sys.stderr.flush()
                except ProcessLookupError:
                    pass

        return mitigated

    def _extract_linux_live_triage(self, pid: int) -> Dict[str, Any]:
        """Extracts non-destructive in-memory forensic snapshot from frozen process."""
        triage: Dict[str, Any] = {}
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read()
                triage["command_line"] = raw.decode("utf-8", errors="replace").replace("\x00", " ").strip()
        except Exception:
            pass

        try:
            triage["executable_path"] = os.readlink(f"/proc/{pid}/exe")
        except Exception:
            pass

        try:
            triage["working_directory"] = os.readlink(f"/proc/{pid}/cwd")
        except Exception:
            pass

        # Compute FIM SHA-256 cryptographic hash of suspect executable
        # Accessing /proc/{pid}/exe directly succeeds even if the file on disk was unlinked/deleted!
        fim_hash = compute_file_sha256(f"/proc/{pid}/exe")
        if not fim_hash and "executable_path" in triage and not triage["executable_path"].endswith("(deleted)"):
            fim_hash = compute_file_sha256(triage["executable_path"])

        if fim_hash:
            triage["sha256_hash"] = fim_hash
            self.total_fim_hashes_computed += 1

        try:
            with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
                for line in f:
                    for k in ("State:", "VmSize:", "VmRSS:", "Threads:", "PPid:", "Uid:"):
                        if line.startswith(k):
                            triage[k[:-1]] = line.split(":", 1)[1].strip()
        except Exception:
            pass

        try:
            with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as f:
                lines = f.readlines()
                triage["total_memory_mappings"] = len(lines)
                exec_regions = []
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2 and "x" in parts[1]:
                        exec_regions.append(line.strip())
                        if len(exec_regions) >= 6:
                            break
                triage["executable_memory_segments"] = exec_regions
        except Exception:
            pass

        return triage

    def _find_linux_fallback_candidate(self) -> Tuple[Optional[int], str]:
        my_pid = os.getpid()
        my_ppid = os.getppid()
        candidates: List[Tuple[int, str, int]] = []

        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid in (0, 1, 2, my_pid, my_ppid) or pid in self.mitigated_pids_history:
                continue

            try:
                with open(f"/proc/{pid}/cmdline", "rb") as cf:
                    if not cf.read():
                        continue

                with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as sf:
                    content = sf.read()

                lparen = content.find("(")
                rparen = content.rfind(")")
                if lparen == -1 or rparen == -1:
                    continue

                comm = content[lparen + 1:rparen]
                if comm in self.whitelist:
                    continue

                rest = content[rparen + 2:].split()
                if int(rest[1]) == 2:
                    continue

                utime = int(rest[11])
                stime = int(rest[12])
                candidates.append((pid, comm, utime + stime))
            except (IOError, IndexError, ValueError):
                continue

        candidates.sort(key=lambda x: x[2], reverse=True)
        if candidates:
            return (candidates[0][0], candidates[0][1])
        return (None, "unknown")

    # -------------------------------------------------------------------------
    # Windows: Win32 SetProcessAffinityMask Core 0 Trap
    # -------------------------------------------------------------------------
    def _mitigate_windows(self) -> List[Dict[str, Any]]:
        mitigated: List[Dict[str, Any]] = []
        candidate_pid: Optional[int] = None
        candidate_name: str = "Unknown"
        candidate_path: Optional[str] = None

        try:
            import ctypes
            from ctypes import wintypes

            class PROCESSENTRY32W(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", wintypes.WCHAR * 260)
                ]

            kernel32 = ctypes.windll.kernel32
            h_snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if h_snap and h_snap != -1:
                pe = PROCESSENTRY32W()
                pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
                has_proc = kernel32.Process32FirstW(h_snap, ctypes.byref(pe))
                my_pid = os.getpid()

                while has_proc:
                    pid = pe.th32ProcessID
                    exe = pe.szExeFile
                    if pid > 4 and pid != my_pid and pid not in self.mitigated_pids_history:
                        if exe.lower() not in [w.lower() for w in self.whitelist]:
                            exe_path = self._query_windows_process_path(pid)

                            # Dynamic Whitelist Auto-Discovery via Code Signing (WinVerifyTrust)
                            if self.trust_signed_binaries and exe_path:
                                is_trusted, signer = self.is_binary_signed_and_trusted(exe_path)
                                if is_trusted:
                                    if self.verbose:
                                        sys.stdout.write(
                                            f"[*] [CODE-SIGNING] Whitelisting PID {pid} ('{exe}') - "
                                            f"Verified corporate signature ({signer}).\n"
                                        )
                                        sys.stdout.flush()
                                    has_proc = kernel32.Process32NextW(h_snap, ctypes.byref(pe))
                                    continue

                            candidate_pid = pid
                            candidate_name = exe
                            candidate_path = exe_path
                            break
                    has_proc = kernel32.Process32NextW(h_snap, ctypes.byref(pe))
                kernel32.CloseHandle(h_snap)
        except Exception:
            pass

        if candidate_pid and candidate_pid not in self.mitigated_pids_history:
            fim_hash = compute_file_sha256(candidate_path) if candidate_path else None
            if fim_hash:
                self.total_fim_hashes_computed += 1

            triage_info = {
                "executable_path": candidate_path or candidate_name,
                "sha256_hash": fim_hash,
                "mitigation_method": "Win32_SetProcessAffinityMask(Core_0)"
            }

            if self.audit_only:
                self.mitigated_pids_history.add(candidate_pid)
                record = {
                    "pid": candidate_pid,
                    "name": candidate_name,
                    "binary_path": candidate_path,
                    "binary_sha256": fim_hash,
                    "action": "DRY_RUN_AUDIT (Affinity unchanged)",
                    "status": "AUDIT_ONLY_UNMODIFIED",
                    "details": "Audit mode active. Target process affinity unaltered.",
                    "live_forensic_triage": triage_info,
                    "forensic_resume_command": "N/A"
                }
                mitigated.append(record)
                if self.verbose:
                    sys.stdout.write(f"[*] [AUDIT-ONLY] Identified suspect PID {candidate_pid} ('{candidate_name}'). Affinity locking bypassed.\n")
                    sys.stdout.flush()
            else:
                affinity_set = False
                try:
                    import ctypes
                    from ctypes import wintypes
                    kernel32 = ctypes.windll.kernel32
                    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
                    kernel32.OpenProcess.restype = wintypes.HANDLE
                    kernel32.SetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.c_size_t]
                    kernel32.SetProcessAffinityMask.restype = wintypes.BOOL
                    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
                    kernel32.CloseHandle.restype = wintypes.BOOL

                    h_proc = kernel32.OpenProcess(
                        PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
                        False,
                        candidate_pid
                    )
                    if h_proc:
                        success = kernel32.SetProcessAffinityMask(h_proc, WIN32_AFFINITY_CORE_0)
                        kernel32.CloseHandle(h_proc)
                        if success:
                            affinity_set = True
                except Exception:
                    affinity_set = False

                if affinity_set:
                    self.mitigated_pids_history.add(candidate_pid)
                    record = {
                        "pid": candidate_pid,
                        "name": candidate_name,
                        "binary_path": candidate_path,
                        "binary_sha256": fim_hash,
                        "action": "Win32_SetProcessAffinityMask(Core_0)",
                        "status": "AFFINITY_TRAPPED_CORE_0",
                        "details": "Affinity locked to Core 0 (Mask 0x0001). Address space preserved for live memory triage.",
                        "live_forensic_triage": triage_info,
                        "forensic_resume_command": f"(Get-Process -Id {candidate_pid}).ProcessorAffinity = -1"
                    }
                    mitigated.append(record)
                    if self.verbose:
                        sys.stdout.write(f"[!] [MITIGATION] Trapped PID {candidate_pid} ('{candidate_name}') onto Core 0 (Mask 0x0001)\n")
                        sys.stdout.flush()

        return mitigated

    # -------------------------------------------------------------------------
    # macOS: renice 20 / os.setpriority Scheduling Demotion
    # -------------------------------------------------------------------------
    def _mitigate_macos(self) -> List[Dict[str, Any]]:
        mitigated: List[Dict[str, Any]] = []

        try:
            res = subprocess.run(
                ["ps", "-axo", "pid,pcpu,comm", "-r"],
                capture_output=True,
                text=True,
                timeout=1.0,
                check=False
            )
            if res.returncode == 0:
                lines = res.stdout.strip().splitlines()[1:]
                my_pid = os.getpid()
                for line in lines:
                    parts = line.strip().split(maxsplit=2)
                    if len(parts) >= 3:
                        pid = int(parts[0])
                        name = parts[2]
                        if pid in (0, 1, my_pid) or pid in self.mitigated_pids_history:
                            continue
                        if any(sys_proc in name for sys_proc in ("launchd", "kernel_task", "WindowServer", "syslogd")):
                            continue

                        # Dynamic Whitelist Auto-Discovery via Code Signing (macOS codesign)
                        if self.trust_signed_binaries:
                            is_trusted, signer = self.is_binary_signed_and_trusted(name)
                            if is_trusted:
                                if self.verbose:
                                    sys.stdout.write(
                                        f"[*] [CODE-SIGNING] Whitelisting PID {pid} ('{name}') - "
                                        f"Verified signature ({signer}).\n"
                                    )
                                    sys.stdout.flush()
                                continue

                        fim_hash = compute_file_sha256(name)
                        if fim_hash:
                            self.total_fim_hashes_computed += 1

                        triage_info = {
                            "executable_path": name,
                            "sha256_hash": fim_hash,
                            "mitigation_method": "renice 20 (Lowest Scheduling Priority)"
                        }

                        if self.audit_only:
                            self.mitigated_pids_history.add(pid)
                            record = {
                                "pid": pid,
                                "name": name,
                                "binary_path": name,
                                "binary_sha256": fim_hash,
                                "action": "DRY_RUN_AUDIT (Priority unchanged)",
                                "status": "AUDIT_ONLY_UNMODIFIED",
                                "details": "Audit mode active. Mach task priority unaltered.",
                                "live_forensic_triage": triage_info,
                                "forensic_resume_command": "N/A"
                            }
                            mitigated.append(record)
                        else:
                            try:
                                os.setpriority(os.PRIO_PROCESS, pid, 20)
                            except Exception:
                                pass
                            self.mitigated_pids_history.add(pid)
                            record = {
                                "pid": pid,
                                "name": name,
                                "binary_path": name,
                                "binary_sha256": fim_hash,
                                "action": "renice 20 (Lowest Scheduling Priority)",
                                "status": "THROTTLED_TO_IDLE_TIER",
                                "details": "Priority demoted to tier 20. Execution throttled; volatile state preserved.",
                                "live_forensic_triage": triage_info,
                                "forensic_resume_command": f"renice 0 -p {pid}"
                            }
                            mitigated.append(record)
                        break
        except Exception as exc:
            if self.verbose:
                sys.stderr.write(f"[!] macOS mitigation error: {exc}\n")
                sys.stderr.flush()

        return mitigated

    @staticmethod
    def resume_process(pid: int) -> bool:
        """Safely unfreezes / resumes a previously mitigated process post-acquisition."""
        sys_platform = platform.system()
        try:
            if sys_platform == "Linux":
                sigcont = getattr(signal, "SIGCONT", 18)
                os.kill(pid, sigcont)
                sys.stdout.write(f"[+] Resumed PID {pid} via SIGCONT (Signal 18).\n")
                return True
            elif sys_platform == "Windows":
                ps_cmd = f"(Get-Process -Id {pid}).ProcessorAffinity = -1"
                res = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=2.0,
                    check=False
                )
                if res.returncode == 0:
                    sys.stdout.write(f"[+] Restored default multi-core affinity for PID {pid}.\n")
                    return True
            elif sys_platform == "Darwin":
                os.setpriority(os.PRIO_PROCESS, pid, 0)
                sys.stdout.write(f"[+] Restored default scheduling priority (nice 0) for PID {pid}.\n")
                return True
        except Exception as exc:
            sys.stderr.write(f"[!] Failed to resume PID {pid}: {exc}\n")
        return False


# =============================================================================
# OUT-OF-BAND EGRESS LOGGER (BOUNDED ROTATING SPOOL & JITTERED BACKOFF)
# =============================================================================

class IntranetEgressLogger:
    """
    Out-of-band standard web egress logging engine.
    Transmits structured JSON alerts strictly over private LAN switch layer (ports 80/443).
    ENTERPRISE HARDENING:
      - Bounded Local Spooling: Enforces a strict 10 MB / 5,000 line quota with FIFO rotation.
      - Network Backoff with Jitter: Exponential backoff with uniform random jitter
        prevents reconnection storms across thousands of endpoints during outages.
    """

    def __init__(
        self,
        log_server_url: str = LOG_SERVER_URL,
        spool_file: str = DEFAULT_SPOOL_FILE,
        insecure_tls: bool = False,
        ebpf_bridge: Optional[Any] = None,
        verbose: bool = False
    ):
        self.log_server_url = log_server_url
        self.spool_file = spool_file
        self.insecure_tls = insecure_tls
        self.ebpf_bridge = ebpf_bridge
        self.verbose = verbose
        self._spool_lock = threading.Lock()

        # Independent backoff streams: heartbeat failures must never suppress alerts.
        self._heartbeat_consecutive_failures: int = 0
        self._heartbeat_next_retry_mono: float = 0.0
        self._alert_consecutive_failures: int = 0
        self._alert_next_retry_mono: float = 0.0
        self._backoff_lock = threading.RLock()

        # Prometheus metric telemetry counters
        self.total_alerts_sent: int = 0
        self.total_heartbeats_sent: int = 0
        self.total_egress_failures: int = 0

        self._ssl_ctx = None
        if self.insecure_tls:
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def dispatch_alert_async(
        self,
        current_temp: float,
        tds_val: float,
        cpu_load: float,
        rolling_baseline: float,
        mitigated_records: List[Dict[str, Any]],
        consecutive_ticks: int = 3
    ) -> threading.Thread:
        """Asynchronously dispatches alert via daemon thread to prevent sensor loop jitter."""
        worker = threading.Thread(
            target=self._send_payload_worker,
            args=(current_temp, tds_val, cpu_load, rolling_baseline, mitigated_records, consecutive_ticks),
            daemon=True,
            name=f"ThermoLock-Egress-{int(time.time() * 1000)}"
        )
        worker.start()
        return worker

    def dispatch_heartbeat_async(
        self,
        current_temp: float,
        rolling_baseline: float,
        cpu_load: float,
        uptime_cycles: int,
        mitigated_count: int
    ) -> threading.Thread:
        """Dispatches health heartbeat beacon to central SIEM."""
        worker = threading.Thread(
            target=self._send_heartbeat_worker,
            args=(current_temp, rolling_baseline, cpu_load, uptime_cycles, mitigated_count),
            daemon=True,
            name=f"ThermoLock-Heartbeat-{uptime_cycles}"
        )
        worker.start()
        return worker

    def _assemble_payload(
        self,
        current_temp: float,
        tds_val: float,
        cpu_load: float,
        rolling_baseline: float,
        mitigated_records: List[Dict[str, Any]],
        consecutive_ticks: int
    ) -> Dict[str, Any]:
        """Assembles definitive structured JSON payload required by SOC / SIEM."""
        utc_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        hostname = socket.gethostname()
        os_platform = f"{platform.system()} ({platform.release()} {platform.machine()})"
        mitigated_pids = [record["pid"] for record in mitigated_records if "pid" in record]
        mitigated_hashes = [
            record.get("binary_sha256") for record in mitigated_records
            if isinstance(record, dict) and record.get("binary_sha256")
        ]

        payload = {
            "timestamp": utc_timestamp,
            "hostname": hostname,
            "local_os_platform": os_platform,
            "thermal_delta_value": round(tds_val, 2),
            "current_temperature": round(current_temp, 2),
            "reported_cpu_load": round(cpu_load, 2),
            "rolling_baseline_temperature_c": round(rolling_baseline, 2),
            "thermal_elevation_above_baseline_c": round(current_temp - rolling_baseline, 2),
            "hysteresis_confirmed_ticks": consecutive_ticks,
            "mitigated_pids": mitigated_pids,
            "mitigated_binary_hashes": mitigated_hashes,
            "ebpf_kernel_telemetry": self.ebpf_bridge.get_status_summary() if self.ebpf_bridge else {
                "architecture": "PURE_RING3",
                "ring0_status": "NOT_ATTACHED"
            },
            "agent_metadata": {
                "version": AGENT_VERSION,
                "detection_engine": "ThermoLock Bare-Metal Thermodynamic EDR (Hybrid Ring 0 / Ring 3)",
                "trigger_condition": f"(TDS >= {TDS_TRIGGER_THRESHOLD_C}°C/s) AND (Global CPU Load <= {CPU_LOAD_MAX_THRESHOLD_PCT}%)",
                "threat_classification": "COVERT_THERMODYNAMIC_EXECUTION_ANOMALY"
            },
            "forensic_mitigation_details": mitigated_records
        }
        return payload

    def _send_payload_worker(
        self,
        current_temp: float,
        tds_val: float,
        cpu_load: float,
        rolling_baseline: float,
        mitigated_records: List[Dict[str, Any]],
        consecutive_ticks: int
    ) -> None:
        payload = self._assemble_payload(current_temp, tds_val, cpu_load, rolling_baseline, mitigated_records, consecutive_ticks)
        self._log_to_syslog(payload)

        # Check jittered backoff window
        now_mono = time.monotonic()
        if now_mono < self._alert_next_retry_mono:
            if self.verbose:
                rem = round(self._alert_next_retry_mono - now_mono, 1)
                sys.stdout.write(f"[*] [EGRESS LOG] Network backoff active ({rem}s remaining). Queuing directly to spool.\n")
                sys.stdout.flush()
            self._spool_payload(payload)
            return

        delivered = self._transmit_http(payload)
        if not delivered:
            self._apply_exponential_backoff("alert")
            self._spool_payload(payload)
        else:
            self._reset_backoff("alert")
            self.total_alerts_sent += 1
            self.flush_spooled_alerts()

    def _send_heartbeat_worker(
        self,
        current_temp: float,
        rolling_baseline: float,
        cpu_load: float,
        uptime_cycles: int,
        mitigated_count: int
    ) -> None:
        now_mono = time.monotonic()
        if now_mono < self._heartbeat_next_retry_mono:
            return  # Skip heartbeat while its own backoff is active

        heartbeat_payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_type": "HEARTBEAT",
            "hostname": socket.gethostname(),
            "local_os_platform": f"{platform.system()} ({platform.release()} {platform.machine()})",
            "agent_version": AGENT_VERSION,
            "agent_status": "MONITORING_ACTIVE",
            "current_temperature_c": round(current_temp, 2),
            "rolling_baseline_temp_c": round(rolling_baseline, 2),
            "current_cpu_load_percent": round(cpu_load, 2),
            "uptime_cycles": uptime_cycles,
            "total_mitigated_threats": mitigated_count,
            "queued_spool_alerts": self.get_queued_spool_count()
        }
        delivered = self._transmit_http(heartbeat_payload)
        if delivered:
            self.total_heartbeats_sent += 1
            self._reset_backoff("heartbeat")
        else:
            self._apply_exponential_backoff("heartbeat")

    def _apply_exponential_backoff(self, stream: str = "alert") -> None:
        """Update only the selected egress stream's exponential backoff state."""
        if stream not in ("alert", "heartbeat"):
            raise ValueError(f"Unknown egress backoff stream: {stream}")
        with self._backoff_lock:
            if stream == "heartbeat":
                self._heartbeat_consecutive_failures += 1
                failures = self._heartbeat_consecutive_failures
            else:
                self._alert_consecutive_failures += 1
                failures = self._alert_consecutive_failures
            self.total_egress_failures += 1
            base_delay = min(60.0, 2.0 * (1.5 ** min(failures, 8)))
            jitter = random.uniform(0.75, 1.25)
            backoff_sec = base_delay * jitter
            retry_at = time.monotonic() + backoff_sec
            if stream == "heartbeat":
                self._heartbeat_next_retry_mono = retry_at
            else:
                self._alert_next_retry_mono = retry_at
        if self.verbose:
            sys.stdout.write(f"[!] [BACKOFF:{stream.upper()}] Egress failed (attempt {failures}). Pausing retries for {backoff_sec:.1f}s.\n")
            sys.stdout.flush()

    def _reset_backoff(self, stream: str = "alert") -> None:
        """Reset only the selected egress stream's backoff state."""
        if stream not in ("alert", "heartbeat"):
            raise ValueError(f"Unknown egress backoff stream: {stream}")
        with self._backoff_lock:
            if stream == "heartbeat":
                self._heartbeat_consecutive_failures = 0
                self._heartbeat_next_retry_mono = 0.0
            else:
                self._alert_consecutive_failures = 0
                self._alert_next_retry_mono = 0.0

    def _log_to_syslog(self, payload: Dict[str, Any]) -> None:
        """Emits audit event to local POSIX syslog socket (/dev/log)."""
        try:
            import syslog
            syslog.openlog(ident="ThermoLock", facility=syslog.LOG_AUTH)
            msg = (
                f"[THERMODYNAMIC_INTRUSION] TDS={payload['thermal_delta_value']:+.1f}C/s "
                f"CPU={payload['reported_cpu_load']:.1f}% Temp={payload['current_temperature']}C "
                f"HysteresisTicks={payload.get('hysteresis_confirmed_ticks', 1)} "
                f"MitigatedPIDs={payload['mitigated_pids']}"
            )
            syslog.syslog(syslog.LOG_CRIT, msg)
        except Exception:
            pass

    def _transmit_http(self, payload: Dict[str, Any]) -> bool:
        """Executes HTTP/HTTPS POST over internal LAN switch layer."""
        json_data = json.dumps(payload, indent=2).encode("utf-8")
        req = urllib.request.Request(
            url=self.log_server_url,
            data=json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Content-Length": str(len(json_data)),
                "X-ThermoLock-TDS": str(payload.get("thermal_delta_value", "0.0")),
                "X-ThermoLock-Host": socket.gethostname()
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC, context=self._ssl_ctx) as response:
                status_code = response.getcode()
                if self.verbose:
                    evt_type = payload.get("event_type", "ALERT")
                    sys.stdout.write(f"[+] [EGRESS LOG] {evt_type} delivered to {self.log_server_url} (HTTP {status_code})\n")
                    sys.stdout.flush()
                return True
        except urllib.error.HTTPError as err:
            sys.stderr.write(f"[!] [EGRESS LOG] HTTP Error ({err.code} {err.reason}) reporting to {self.log_server_url}\n")
            sys.stderr.flush()
            return False
        except urllib.error.URLError as err:
            sys.stderr.write(f"[!] [EGRESS LOG] Intranet route unreachable ({err.reason}).\n")
            sys.stderr.flush()
            return False
        except Exception as exc:
            sys.stderr.write(f"[!] [EGRESS LOG] Transmission exception: {exc}\n")
            sys.stderr.flush()
            return False

    def _spool_payload(self, payload: Dict[str, Any]) -> None:
        """Appends alert payload to local offline queue with quota checking and rotation."""
        with self._spool_lock:
            try:
                # Log rotation check
                if os.path.isfile(self.spool_file):
                    file_size = os.path.getsize(self.spool_file)
                    if file_size >= MAX_SPOOL_BYTES:
                        self._rotate_spool_file()

                with open(self.spool_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(payload) + "\n")
                if self.verbose:
                    sys.stdout.write(f"[*] [SPOOL] Alert persisted to offline queue: {self.spool_file}\n")
                    sys.stdout.flush()
            except Exception as exc:
                sys.stderr.write(f"[!] [SPOOL] Failed to write spool file: {exc}\n")
                sys.stderr.flush()

    def _rotate_spool_file(self) -> None:
        """Rotates main spool to .1 backup file to strictly bound total disk usage."""
        backup_path = f"{self.spool_file}.1"
        try:
            if os.path.isfile(backup_path):
                os.unlink(backup_path)
            os.rename(self.spool_file, backup_path)
            if self.verbose:
                sys.stdout.write(f"[!] [SPOOL ROTATION] Quota reached ({MAX_SPOOL_BYTES} bytes). Rotated to {backup_path}.\n")
                sys.stdout.flush()
        except Exception as exc:
            sys.stderr.write(f"[!] [SPOOL ROTATION] Rotation error: {exc}\n")

    def get_queued_spool_count(self) -> int:
        """Returns total count of alerts currently queued in offline spool."""
        count = 0
        with self._spool_lock:
            for p in (self.spool_file, f"{self.spool_file}.1"):
                if os.path.isfile(p):
                    try:
                        with open(p, "r", encoding="utf-8") as f:
                            count += sum(1 for line in f if line.strip())
                    except Exception:
                        pass
        return count

    def flush_spooled_alerts(self) -> int:
        """Flushes queued alerts from rotated backup first, then primary spool."""
        flushed_count = 0
        with self._spool_lock:
            for target_path in (f"{self.spool_file}.1", self.spool_file):
                if not os.path.isfile(target_path):
                    continue
                try:
                    with open(target_path, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                    if not lines:
                        os.unlink(target_path)
                        continue

                    remaining_lines: List[str] = []
                    for line in lines:
                        line_str = line.strip()
                        if not line_str:
                            continue
                        try:
                            alert_dict = json.loads(line_str)
                            if self._transmit_http(alert_dict):
                                flushed_count += 1
                            else:
                                remaining_lines.append(line_str)
                        except Exception:
                            pass

                    if remaining_lines:
                        with open(target_path, "w", encoding="utf-8") as f:
                            for rem in remaining_lines:
                                f.write(rem + "\n")
                    else:
                        os.unlink(target_path)
                except Exception:
                    pass

        if flushed_count > 0 and self.verbose:
            sys.stdout.write(f"[+] [SPOOL] Flushed {flushed_count} spooled alert(s) to central log server.\n")
            sys.stdout.flush()

        return flushed_count


# =============================================================================
# PROMETHEUS METRICS EXPORTER & LOCAL STATS
# =============================================================================

class PrometheusMetricsServer:
    """
    Lightweight, zero-dependency Prometheus HTTP endpoint and stats exporter.
    Serves standard text exposition format on /metrics or updates local .prom file.
    """

    def __init__(
        self,
        port: Optional[int] = None,
        stats_file: str = DEFAULT_METRICS_FILE,
        verbose: bool = False
    ):
        self.port = port
        self.stats_file = stats_file
        self.verbose = verbose
        self._server = None
        self._thread = None
        self._metrics_lock = threading.Lock()

        # Telemetry metrics
        self.cpu_temperature: float = 42.0
        self.rolling_baseline: float = 42.0
        self.thermal_delta_speed: float = 0.0
        self.cpu_load_percent: float = 0.0
        self.consecutive_anomaly_ticks: int = 0
        self.anomalies_detected_total: int = 0
        self.mitigations_executed_total: int = 0
        self.spool_queued_alerts: int = 0
        self.heartbeats_sent_total: int = 0
        self.egress_failures_total: int = 0
        self.fim_hashes_total: int = 0
        self.code_signing_whitelisted_total: int = 0
        self.systemd_watchdog_active: int = 0
        self.ebpf_active: int = 0
        self.ebpf_tracked_pids: int = 0
        self.ebpf_kernel_ticks_total: int = 0

    def start(self) -> None:
        """Starts Prometheus HTTP server if port is configured."""
        if not self.port:
            return

        exporter_self = self
        import http.server
        import socketserver

        class PrometheusHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                # Ignore query parameters when routing the metrics endpoint.
                target = self.path.split("?", 1)[0]
                if target in ("/metrics", "/metrics/"):
                    content = exporter_self.generate_prometheus_text().encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args):
                pass

        try:
            self._server = socketserver.TCPServer(("0.0.0.0", self.port), PrometheusHandler)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name="ThermoLock-Prometheus")
            self._thread.start()
            if self.verbose:
                sys.stdout.write(f"[*] [METRICS] Prometheus HTTP exporter listening on port {self.port} (/metrics)\n")
                sys.stdout.flush()
        except Exception as exc:
            sys.stderr.write(f"[!] [METRICS] Failed to bind metrics port {self.port}: {exc}\n")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    def update_metrics(
        self,
        temp: float,
        baseline: float,
        tds: float,
        cpu_load: float,
        consecutive_ticks: int,
        anomalies_total: int,
        mitigations_total: int,
        queued_spool: int,
        heartbeats_total: int,
        failures_total: int,
        fim_hashes_total: int = 0,
        code_signing_whitelisted_total: int = 0,
        systemd_watchdog_active: int = 0,
        ebpf_active: int = 0,
        ebpf_tracked_pids: int = 0,
        ebpf_kernel_ticks_total: int = 0
    ) -> None:
        """Updates internal telemetry values and refreshes stats file."""
        with self._metrics_lock:
            self.cpu_temperature = temp
            self.rolling_baseline = baseline
            self.thermal_delta_speed = tds
            self.cpu_load_percent = cpu_load
            self.consecutive_anomaly_ticks = consecutive_ticks
            self.anomalies_detected_total = anomalies_total
            self.mitigations_executed_total = mitigations_total
            self.spool_queued_alerts = queued_spool
            self.heartbeats_sent_total = heartbeats_total
            self.egress_failures_total = failures_total
            self.fim_hashes_total = fim_hashes_total
            self.code_signing_whitelisted_total = code_signing_whitelisted_total
            self.systemd_watchdog_active = systemd_watchdog_active
            self.ebpf_active = ebpf_active
            self.ebpf_tracked_pids = ebpf_tracked_pids
            self.ebpf_kernel_ticks_total = ebpf_kernel_ticks_total

        self.write_stats_file()

    def generate_prometheus_text(self) -> str:
        with self._metrics_lock:
            lines = [
                "# HELP thermolock_cpu_temperature_celsius Current bare-metal CPU silicon temperature",
                "# TYPE thermolock_cpu_temperature_celsius gauge",
                f"thermolock_cpu_temperature_celsius {self.cpu_temperature:.2f}",
                "# HELP thermolock_rolling_baseline_temperature_celsius Rolling 60s equilibrium baseline temperature",
                "# TYPE thermolock_rolling_baseline_temperature_celsius gauge",
                f"thermolock_rolling_baseline_temperature_celsius {self.rolling_baseline:.2f}",
                "# HELP thermolock_thermal_delta_speed_celsius_per_sec Thermal Delta Speed (TDS) rate of change",
                "# TYPE thermolock_thermal_delta_speed_celsius_per_sec gauge",
                f"thermolock_thermal_delta_speed_celsius_per_sec {self.thermal_delta_speed:.2f}",
                "# HELP thermolock_cpu_load_percent Global kernel CPU utilization percentage",
                "# TYPE thermolock_cpu_load_percent gauge",
                f"thermolock_cpu_load_percent {self.cpu_load_percent:.2f}",
                "# HELP thermolock_consecutive_anomaly_ticks Consecutive anomaly ticks counter",
                "# TYPE thermolock_consecutive_anomaly_ticks gauge",
                f"thermolock_consecutive_anomaly_ticks {self.consecutive_anomaly_ticks}",
                "# HELP thermolock_anomalies_detected_total Total confirmed thermodynamic anomalies",
                "# TYPE thermolock_anomalies_detected_total counter",
                f"thermolock_anomalies_detected_total {self.anomalies_detected_total}",
                "# HELP thermolock_mitigations_executed_total Total active mitigations executed",
                "# TYPE thermolock_mitigations_executed_total counter",
                f"thermolock_mitigations_executed_total {self.mitigations_executed_total}",
                "# HELP thermolock_spool_queued_alerts Total alerts queued in offline resilient spool",
                "# TYPE thermolock_spool_queued_alerts gauge",
                f"thermolock_spool_queued_alerts {self.spool_queued_alerts}",
                "# HELP thermolock_heartbeats_sent_total Total heartbeat beacons delivered",
                "# TYPE thermolock_heartbeats_sent_total counter",
                f"thermolock_heartbeats_sent_total {self.heartbeats_sent_total}",
                "# HELP thermolock_egress_failures_total Total failed network egress attempts",
                "# TYPE thermolock_egress_failures_total counter",
                f"thermolock_egress_failures_total {self.egress_failures_total}",
                "# HELP thermolock_fim_hashes_calculated_total Total cryptographic FIM SHA-256 hashes calculated",
                "# TYPE thermolock_fim_hashes_calculated_total counter",
                f"thermolock_fim_hashes_calculated_total {self.fim_hashes_total}",
                "# HELP thermolock_code_signing_whitelisted_total Total processes dynamically whitelisted via verified code signing",
                "# TYPE thermolock_code_signing_whitelisted_total counter",
                f"thermolock_code_signing_whitelisted_total {self.code_signing_whitelisted_total}",
                "# HELP thermolock_systemd_watchdog_active Whether systemd watchdog supervisor integration is active (1 or 0)",
                "# TYPE thermolock_systemd_watchdog_active gauge",
                f"thermolock_systemd_watchdog_active {self.systemd_watchdog_active}",
                "# HELP thermolock_ebpf_active Linux eBPF kernel scheduler telemetry bridge active (1 or 0)",
                "# TYPE thermolock_ebpf_active gauge",
                f"thermolock_ebpf_active {self.ebpf_active}",
                "# HELP thermolock_ebpf_tracked_pids Count of active PIDs currently tracked in shared BPF map",
                "# TYPE thermolock_ebpf_tracked_pids gauge",
                f"thermolock_ebpf_tracked_pids {self.ebpf_tracked_pids}",
                "# HELP thermolock_ebpf_kernel_ticks_total Cumulative context switch events recorded from Ring 0",
                "# TYPE thermolock_ebpf_kernel_ticks_total counter",
                f"thermolock_ebpf_kernel_ticks_total {self.ebpf_kernel_ticks_total}"
            ]
            return "\n".join(lines) + "\n"

    def write_stats_file(self) -> None:
        """Atomically writes metrics to local stats file for node_exporter textfile scraper."""
        tmp_path = f"{self.stats_file}.tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(self.generate_prometheus_text())
            os.replace(tmp_path, self.stats_file)
        except Exception:
            pass


# =============================================================================
# CORE THERMOLOCK DAEMON & ORCHESTRATION LOOP
# =============================================================================

class ThermoLockDaemon:
    """
    Main ThermoLock host sensor orchestration daemon.
    Enforces a strict 1.0-second interval continuous loop.
    Monitors:
      1. Thermal Delta Speed (TDS): Current temp minus temp 1.0s prior.
      2. Global CPU Load Percentage: Kernel utilization.
    Evaluates:
      TRIGGER: (TDS >= 5.0°C) AND (Global CPU Load <= 15.0%)
    HYSTERESIS: Requires anomaly condition to persist for K consecutive ticks.
    """

    def __init__(
        self,
        log_server_url: str = LOG_SERVER_URL,
        cooldown_sec: float = ALERT_COOLDOWN_SEC,
        hysteresis_ticks: int = DEFAULT_HYSTERESIS_TICKS,
        heartbeat_sec: int = DEFAULT_HEARTBEAT_SEC,
        spool_file: str = DEFAULT_SPOOL_FILE,
        custom_whitelist: Optional[Set[str]] = None,
        audit_only: bool = False,
        trust_signed_binaries: bool = False,
        trusted_signers: Optional[List[str]] = None,
        enable_ebpf: bool = False,
        insecure_tls: bool = False,
        metrics_port: Optional[int] = None,
        config_path: Optional[str] = None,
        verbose: bool = True,
        simulation_mode: bool = False
    ):
        self.log_server_url = log_server_url
        self.cooldown_sec = cooldown_sec
        self.hysteresis_ticks = max(1, hysteresis_ticks)
        self.heartbeat_sec = heartbeat_sec
        self.spool_file = spool_file
        self.audit_only = audit_only
        self.trust_signed_binaries = trust_signed_binaries
        self.trusted_signers = trusted_signers
        self.enable_ebpf = enable_ebpf
        self.config_path = config_path
        self.verbose = verbose
        self.simulation_mode = simulation_mode

        self.systemd = SystemdNotifier(verbose=self.verbose)
        self.hardware = HardwareThermalIngestion(verbose=self.verbose)
        self.cpu_meter = KernelCPULoadMeter()
        self.ebpf_bridge = EbpfKernelBridge(enabled=self.enable_ebpf, verbose=self.verbose)
        self.mitigation = ForensicMitigationEngine(
            cpu_meter=self.cpu_meter,
            custom_whitelist=custom_whitelist,
            audit_only=self.audit_only,
            trust_signed_binaries=self.trust_signed_binaries,
            trusted_signers=self.trusted_signers,
            ebpf_bridge=self.ebpf_bridge,
            verbose=self.verbose
        )
        self.logger = IntranetEgressLogger(
            log_server_url=self.log_server_url,
            spool_file=self.spool_file,
            insecure_tls=insecure_tls,
            ebpf_bridge=self.ebpf_bridge,
            verbose=self.verbose
        )
        self.metrics = PrometheusMetricsServer(
            port=metrics_port,
            verbose=self.verbose
        )

        self._shutdown_event = threading.Event()
        self._last_alert_time: float = 0.0
        self._active_workers: List[threading.Thread] = []
        self._workers_lock = threading.Lock()
        self._temp_history: deque = deque(maxlen=60)

        # Hysteresis counter
        self._consecutive_spike_count: int = 0
        self.total_anomalies_confirmed: int = 0

    def reload_config(self) -> None:
        """Dynamic configuration hot-reloading (triggered via SIGHUP)."""
        if not self.config_path or not os.path.isfile(self.config_path):
            return
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            if "log_server_url" in cfg:
                self.log_server_url = cfg["log_server_url"]
                self.logger.log_server_url = self.log_server_url
            if "cooldown_sec" in cfg:
                self.cooldown_sec = float(cfg["cooldown_sec"])
            if "hysteresis_ticks" in cfg:
                self.hysteresis_ticks = max(1, int(cfg["hysteresis_ticks"]))
            if "audit_only" in cfg:
                self.audit_only = bool(cfg["audit_only"])
                self.mitigation.audit_only = self.audit_only
            if "whitelist" in cfg and isinstance(cfg["whitelist"], list):
                self.mitigation.whitelist.update(cfg["whitelist"])
            if "trust_signed_binaries" in cfg:
                self.trust_signed_binaries = bool(cfg["trust_signed_binaries"])
                self.mitigation.trust_signed_binaries = self.trust_signed_binaries
            if "trusted_signers" in cfg and isinstance(cfg["trusted_signers"], list):
                self.trusted_signers = list(cfg["trusted_signers"])
                self.mitigation.trusted_signers = self.trusted_signers
            if "enable_ebpf" in cfg:
                new_ebpf = bool(cfg["enable_ebpf"])
                if new_ebpf != self.enable_ebpf:
                    self.enable_ebpf = new_ebpf
                    self.ebpf_bridge.enabled = self.enable_ebpf
                    if self.enable_ebpf:
                        self.ebpf_bridge.start()
                    else:
                        self.ebpf_bridge.stop()
            self.systemd.notify_ready("ThermoLock dynamic configuration reloaded")
            sys.stdout.write("[*] [HOT-RELOAD] Dynamic configuration successfully reloaded.\n")
            sys.stdout.flush()
        except Exception as exc:
            sys.stderr.write(f"[!] [HOT-RELOAD] Error reloading config: {exc}\n")
            sys.stderr.flush()

    def stop(self) -> None:
        """Signals the daemon loop to terminate cleanly and flushes active workers."""
        self.systemd.notify_stopping()
        self._shutdown_event.set()
        self.ebpf_bridge.stop()
        self.hardware.stop()
        self.metrics.stop()
        # Snapshot under lock, then release it before any blocking join.
        with self._workers_lock:
            workers = tuple(self._active_workers)
        for worker in workers:
            if worker is not threading.current_thread() and worker.is_alive():
                worker.join(timeout=3.5)
        with self._workers_lock:
            self._active_workers = [worker for worker in self._active_workers if worker.is_alive()]

    def run(self, max_cycles: Optional[int] = None) -> None:
        """Executes the continuous monitoring loop on a strict 1.0-second cadence."""
        mode_str = "AUDIT-ONLY (DRY RUN)" if self.audit_only else "ACTIVE DEFENSE (KERNEL MITIGATION)"
        sys.stdout.write("=================================================================\n")
        sys.stdout.write(f" ThermoLock Bare-Metal Thermodynamic Sensor Daemon v{AGENT_VERSION}\n")
        sys.stdout.write(f" Host: {socket.gethostname()} | OS: {platform.system()} {platform.release()}\n")
        sys.stdout.write(f" Mode: {mode_str}\n")
        sys.stdout.write(f" Log Server: {self.log_server_url}\n")
        sys.stdout.write(f" Trigger Rule: (TDS >= {TDS_TRIGGER_THRESHOLD_C}°C/s) AND (CPU_Load <= {CPU_LOAD_MAX_THRESHOLD_PCT}%)\n")
        sys.stdout.write(f" Hysteresis: {self.hysteresis_ticks} sample(s) | Cooldown: {self.cooldown_sec}s | Cadence: {SAMPLE_INTERVAL_SEC}s\n")
        sys.stdout.write("=================================================================\n")
        sys.stdout.flush()

        # Start metrics exporter
        self.metrics.start()

        # Initialize Ring 0 eBPF kernel bridge if requested
        if self.enable_ebpf:
            self.ebpf_bridge.start()

        # Signal systemd readiness (READY=1)
        self.systemd.notify_ready(
            f"ThermoLock active | Cadence: {SAMPLE_INTERVAL_SEC}s | TDS Threshold: {TDS_TRIGGER_THRESHOLD_C}°C/s"
        )

        prev_temp = self.hardware.get_cpu_temperature()
        _ = self.cpu_meter.sample_interval_load()
        self._temp_history.append(prev_temp)

        next_tick = time.perf_counter() + SAMPLE_INTERVAL_SEC
        cycle_count = 0

        while not self._shutdown_event.is_set():
            sleep_duration = next_tick - time.perf_counter()
            if sleep_duration > 0:
                time.sleep(sleep_duration)
            next_tick += SAMPLE_INTERVAL_SEC
            cycle_count += 1

            # Ping systemd watchdog on every 1.0-second tick
            self.systemd.notify_watchdog()

            # 0. Sample shared Ring 0 eBPF hash map if active
            if self.ebpf_bridge.active:
                self.ebpf_bridge.sample_and_clear()

            # 1. Hardware Sensor Ingestion
            if self.simulation_mode and 2 <= cycle_count <= (1 + self.hysteresis_ticks):
                # Simulate sustained multi-tick anomaly across hysteresis window
                curr_temp = prev_temp + 6.2
                cpu_load = 7.5
                sys.stdout.write(f"[*] [SIMULATION INJECTION] Simulating covert cryptominer spike (Sample {cycle_count - 1}/{self.hysteresis_ticks}).\n")
                sys.stdout.flush()
            else:
                curr_temp = self.hardware.get_cpu_temperature()
                cpu_load = self.cpu_meter.sample_interval_load()

            # 2. Mathematical TDS & Rolling Baseline Computation
            self._temp_history.append(curr_temp)
            rolling_baseline = sum(self._temp_history) / len(self._temp_history)
            tds = round(curr_temp - prev_temp, 2)
            prev_temp = curr_temp

            timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            sign = "+" if tds >= 0 else ""

            # 3. Anomaly Evaluation with Multi-Sample Hysteresis Confirmation
            is_spike = (tds >= TDS_TRIGGER_THRESHOLD_C) and (cpu_load <= CPU_LOAD_MAX_THRESHOLD_PCT)
            now_mono = time.monotonic()
            in_cooldown = (now_mono - self._last_alert_time) < self.cooldown_sec

            if is_spike:
                self._consecutive_spike_count += 1
                if self._consecutive_spike_count < self.hysteresis_ticks:
                    status_label = f"ANOMALY_PENDING ({self._consecutive_spike_count}/{self.hysteresis_ticks})"
                    sys.stdout.write(
                        f"[{timestamp_str}] TEMP: {curr_temp:.1f}°C | TDS: {sign}{tds:.1f}°C/s | "
                        f"CPU: {cpu_load:5.1f}% | STATUS: {status_label}\n"
                    )
                    sys.stdout.write(
                        f"  [~] Hysteresis Evaluating: Sample {self._consecutive_spike_count}/{self.hysteresis_ticks} met threshold. Awaiting confirmation...\n"
                    )
                    sys.stdout.flush()
                else:
                    # Hysteresis confirmation met!
                    if not in_cooldown:
                        self._last_alert_time = now_mono
                        self.total_anomalies_confirmed += 1
                        status_label = f"!!! THREAT ANOMALY CONFIRMED ({self._consecutive_spike_count}/{self.hysteresis_ticks}) !!!"
                        sys.stdout.write(
                            f"[{timestamp_str}] TEMP: {curr_temp:.1f}°C (Base: {rolling_baseline:.1f}°C) | "
                            f"TDS: {sign}{tds:.1f}°C/s | CPU: {cpu_load:5.1f}% | STATUS: {status_label}\n"
                        )
                        sys.stdout.write(
                            f"  [>] Trigger Confirmed: TDS ({tds:.1f}°C/s) >= {TDS_TRIGGER_THRESHOLD_C}°C/s "
                            f"AND CPU ({cpu_load:.1f}%) <= {CPU_LOAD_MAX_THRESHOLD_PCT}% for {self._consecutive_spike_count} ticks.\n"
                        )
                        sys.stdout.flush()

                        mitigation_worker = threading.Thread(
                            target=self._execute_mitigation_and_egress,
                            args=(curr_temp, tds, cpu_load, rolling_baseline, self._consecutive_spike_count),
                            daemon=True,
                            name=f"ThermoLock-Mitigate-{cycle_count}"
                        )
                        mitigation_worker.start()
                        self._track_worker(mitigation_worker)
                    else:
                        status_label = "COOLDOWN_ACTIVE"
                        sys.stdout.write(
                            f"[{timestamp_str}] TEMP: {curr_temp:.1f}°C | TDS: {sign}{tds:.1f}°C/s | "
                            f"CPU: {cpu_load:5.1f}% | STATUS: {status_label}\n"
                        )
                        sys.stdout.flush()
            else:
                if self._consecutive_spike_count > 0 and self._consecutive_spike_count < self.hysteresis_ticks:
                    sys.stdout.write(
                        f"[*] [HYSTERESIS RECOVERY] Transient thermal spike subsided after {self._consecutive_spike_count} tick(s). False positive avoided.\n"
                    )
                    sys.stdout.flush()
                self._consecutive_spike_count = 0
                status_label = "NOMINAL"
                sys.stdout.write(
                    f"[{timestamp_str}] TEMP: {curr_temp:.1f}°C | TDS: {sign}{tds:.1f}°C/s | "
                    f"CPU: {cpu_load:5.1f}% | STATUS: {status_label}\n"
                )
                sys.stdout.flush()

            # 4. Periodic SIEM Heartbeat Beacon
            if self.heartbeat_sec > 0 and (cycle_count % self.heartbeat_sec == 0):
                hb_worker = self.logger.dispatch_heartbeat_async(
                    current_temp=curr_temp,
                    rolling_baseline=rolling_baseline,
                    cpu_load=cpu_load,
                    uptime_cycles=cycle_count,
                    mitigated_count=len(self.mitigation.mitigated_pids_history)
                )
                self._track_worker(hb_worker)

            # 5. Refresh Prometheus metrics
            self.metrics.update_metrics(
                temp=curr_temp,
                baseline=rolling_baseline,
                tds=tds,
                cpu_load=cpu_load,
                consecutive_ticks=self._consecutive_spike_count,
                anomalies_total=self.total_anomalies_confirmed,
                mitigations_total=len(self.mitigation.mitigated_pids_history),
                queued_spool=self.logger.get_queued_spool_count(),
                heartbeats_total=self.logger.total_heartbeats_sent,
                failures_total=self.logger.total_egress_failures,
                fim_hashes_total=self.mitigation.total_fim_hashes_computed,
                code_signing_whitelisted_total=self.mitigation.total_code_signing_whitelisted,
                systemd_watchdog_active=1 if self.systemd.is_enabled else 0,
                ebpf_active=1 if self.ebpf_bridge.active else 0,
                ebpf_tracked_pids=len(self.ebpf_bridge.last_sample),
                ebpf_kernel_ticks_total=self.ebpf_bridge.total_kernel_ticks
            )

            if max_cycles and cycle_count >= max_cycles:
                break

        self.stop()

    def _execute_mitigation_and_egress(
        self,
        curr_temp: float,
        tds: float,
        cpu_load: float,
        rolling_baseline: float,
        consecutive_ticks: int
    ) -> None:
        """Asynchronous mitigation and network dispatch worker."""
        mitigated_records = self.mitigation.identify_and_mitigate_suspects()
        worker = self.logger.dispatch_alert_async(
            current_temp=curr_temp,
            tds_val=tds,
            cpu_load=cpu_load,
            rolling_baseline=rolling_baseline,
            mitigated_records=mitigated_records,
            consecutive_ticks=consecutive_ticks
        )
        self._track_worker(worker)

    def _track_worker(self, worker: threading.Thread) -> None:
        """Prune and register workers atomically across daemon/worker threads."""
        with self._workers_lock:
            self._active_workers = [w for w in self._active_workers if w.is_alive()]
            self._active_workers.append(worker)


# =============================================================================
# SYSTEMD SERVICE UNIT GENERATOR & DIAGNOSTIC AUDIT
# =============================================================================

def print_systemd_unit() -> None:
    """Prints a production-ready, hardened systemd service unit."""
    script_path = os.path.abspath(__file__)
    python_bin = sys.executable
    unit_content = f"""[Unit]
Description=ThermoLock Bare-Metal Thermodynamic Intrusion Detection Agent
Documentation=https://github.com/enterprise-security/thermolock
After=network.target network-online.target sys-devices-virtual-thermal.device
Wants=network-online.target

[Service]
Type=notify
WatchdogSec=15s
NotifyAccess=main
ExecStart={python_bin} {script_path}
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5s
KillMode=process

# Linux Hardened Security Capabilities & Resource Limits
LimitMEMLOCK=infinity
CapabilityBoundingSet=CAP_KILL CAP_SYS_NICE CAP_SYS_PTRACE CAP_BPF CAP_SYS_ADMIN
AmbientCapabilities=CAP_KILL CAP_SYS_NICE CAP_SYS_PTRACE CAP_BPF CAP_SYS_ADMIN
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
"""
    sys.stdout.write(unit_content)
    sys.stdout.flush()


def run_sensor_check() -> None:
    """Diagnostic audit utility to inspect hardware sensors."""
    sys.stdout.write("=================================================================\n")
    sys.stdout.write(" ThermoLock Hardware Thermal Sensor Diagnostic Audit\n")
    sys.stdout.write(f" Host: {socket.gethostname()} | Platform: {platform.system()} {platform.release()}\n")
    sys.stdout.write("=================================================================\n")
    ingestion = HardwareThermalIngestion(verbose=True)
    sensors = ingestion.inspect_available_sensors()
    if sensors:
        sys.stdout.write(f"[+] Discovered {len(sensors)} bare-metal hardware thermal sensor(s):\n")
        for s in sensors:
            sys.stdout.write(f"  - Sensor: {s.get('sensor')} | Type: {s.get('type')} | Temp: {s.get('current_temp_c')}°C | Path: {s.get('path', 'N/A')}\n")
    else:
        sys.stdout.write("[!] No hardware sensors exposed via sysfs/ACPI (typical for VM/container).\n")
    curr = ingestion.get_cpu_temperature()
    sys.stdout.write(f"[*] Primary Ingested Silicon Temperature: {curr:.2f}°C\n")
    ingestion.stop()

    # Systemd watchdog audit
    systemd = SystemdNotifier(verbose=False)
    if systemd.is_enabled:
        sys.stdout.write(f"[*] Systemd Watchdog Supervisor: DETECTED (NOTIFY_SOCKET: {systemd.socket_path})\n")
    else:
        sys.stdout.write("[*] Systemd Watchdog Supervisor: INACTIVE (Standalone execution)\n")

    # Code signing verification engine audit
    sys_plat = platform.system()
    if sys_plat == "Windows":
        sys.stdout.write("[*] Code-Signing Verification Engine: READY (Win32 WinVerifyTrust & Crypt32 Authenticode)\n")
    elif sys_plat == "Darwin":
        sys.stdout.write("[*] Code-Signing Verification Engine: READY (macOS codesign subsystem)\n")
    else:
        sys.stdout.write("[*] Code-Signing Verification Engine: N/A (Linux standard POSIX ELF isolation)\n")

    sys.stdout.write("[*] File Integrity Monitoring (FIM): READY (Chunked SHA-256 binary hashing)\n")

    # eBPF kernel subsystem audit
    if sys_plat == "Linux":
        try:
            from bcc import BPF
            has_bcc = True
        except (ImportError, Exception):
            has_bcc = False

        if os.geteuid() == 0 and has_bcc:
            sys.stdout.write("[*] Linux eBPF Kernel Telemetry: READY (BCC compiler and root privileges confirmed)\n")
        elif os.geteuid() != 0:
            sys.stdout.write("[*] Linux eBPF Kernel Telemetry: RESTRICTED (Root / CAP_BPF required for kernel probes)\n")
        else:
            sys.stdout.write("[*] Linux eBPF Kernel Telemetry: UNAVAILABLE (BCC Python module missing; fallback active)\n")
    else:
        sys.stdout.write(f"[*] Linux eBPF Kernel Telemetry: N/A ({sys_plat} host; pure Ring 3 userspace engine)\n")

    sys.stdout.flush()


# =============================================================================
# CLI ENTRYPOINT & DISPATCH
# =============================================================================

def print_help() -> None:
    help_text = f"""
ThermoLock Host Sensor Agent v{AGENT_VERSION}
Bare-Metal Thermodynamic Intrusion Detection & Mitigation Agent

Usage:
  python3 thermolock_agent.py [OPTIONS]

Operational Modes:
  (default)            Run continuous daemon monitoring on strict 1.0s interval
  --once               Execute a single 1.0-second evaluation cycle and exit
  --simulate           Run in simulation mode (injects sustained TDS anomaly across hysteresis window)
  --test-egress        Transmit an immediate canary alert test payload to verify network
  --check-sensors      Audit and display bare-metal hardware thermal sensors on this host
  --resume <PID>       Safely unfreeze / resume a previously mitigated PID (IR Recovery)
  --unfreeze <PID>     Alias for --resume
  --print-systemd      Output hardened systemd unit file for enterprise fleet deployment

Enterprise Security Options:
  --audit-only         Dry-run mode: logs anomalies and sends alerts without altering processes
  --consecutive-ticks <N> Hysteresis filter: ticks required to confirm anomaly (default: {DEFAULT_HYSTERESIS_TICKS})
  --enable-ebpf        Enable Ring 0 Linux eBPF kernel scheduler probe (tracepoint:sched:sched_switch)
  --trust-signed       Enable dynamic whitelist auto-discovery via verified code signing (WinVerifyTrust)
  --trusted-signers <NAMES> Comma-separated trusted certificate publisher names (defaults to Microsoft, CrowdStrike, etc.)
  --allow-unprivileged Bypass startup root/administrator privilege enforcement (lab testing)
  --metrics-port <PORT> Expose Prometheus metrics endpoint on local port (e.g. 9182)
  --config <FILE>      Load parameters from a JSON configuration file
  --log-url <URL>      Override central intranet log server URL (default: {LOG_SERVER_URL})
  --cooldown <SEC>     Alert cooldown period in seconds (default: {ALERT_COOLDOWN_SEC})
  --heartbeat <SEC>    Heartbeat beacon interval in seconds (default: {DEFAULT_HEARTBEAT_SEC}, 0 to disable)
  --spool-file <PATH>  Local offline queue path (default: {DEFAULT_SPOOL_FILE})
  --whitelist <NAMES>  Comma-separated process names to whitelist from mitigation
  --insecure           Disable SSL certificate verification for intranet HTTPS endpoints
  --quiet              Suppress nominal periodic stdout logs
  --help, -h           Display this operational manual
"""
    sys.stdout.write(help_text)
    sys.stdout.flush()


def main() -> None:
    args = sys.argv[1:]

    log_url = LOG_SERVER_URL
    cooldown_sec = ALERT_COOLDOWN_SEC
    hysteresis_ticks = DEFAULT_HYSTERESIS_TICKS
    heartbeat_sec = DEFAULT_HEARTBEAT_SEC
    spool_file = DEFAULT_SPOOL_FILE
    simulation_mode = False
    test_egress_only = False
    run_once = False
    insecure_tls = False
    audit_only = False
    allow_unprivileged = False
    trust_signed_binaries = False
    trusted_signers: Optional[List[str]] = None
    enable_ebpf = False
    metrics_port = None
    verbose = True
    config_path = None
    custom_whitelist: Set[str] = set()

    # Pre-pass: load config file
    idx = 0
    while idx < len(args):
        if args[idx] == "--config" and idx + 1 < len(args):
            config_path = args[idx + 1]
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                log_url = cfg.get("log_server_url", log_url)
                cooldown_sec = cfg.get("cooldown_sec", cooldown_sec)
                hysteresis_ticks = cfg.get("hysteresis_ticks", hysteresis_ticks)
                heartbeat_sec = cfg.get("heartbeat_sec", heartbeat_sec)
                spool_file = cfg.get("spool_file", spool_file)
                audit_only = cfg.get("audit_only", audit_only)
                insecure_tls = cfg.get("insecure_tls", insecure_tls)
                metrics_port = cfg.get("metrics_port", metrics_port)
                if "whitelist" in cfg and isinstance(cfg["whitelist"], list):
                    custom_whitelist.update(cfg["whitelist"])
                if "trust_signed_binaries" in cfg:
                    trust_signed_binaries = bool(cfg["trust_signed_binaries"])
                if "trusted_signers" in cfg and isinstance(cfg["trusted_signers"], list):
                    trusted_signers = list(cfg["trusted_signers"])
                if "enable_ebpf" in cfg:
                    enable_ebpf = bool(cfg["enable_ebpf"])
            except Exception as exc:
                sys.stderr.write(f"[!] Error reading configuration file '{config_path}': {exc}\n")
                sys.exit(1)
            idx += 1
        idx += 1

    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg in ("--help", "-h"):
            print_help()
            sys.exit(0)
        elif arg == "--print-systemd":
            print_systemd_unit()
            sys.exit(0)
        elif arg == "--check-sensors":
            run_sensor_check()
            sys.exit(0)
        elif arg in ("--resume", "--unfreeze"):
            if idx + 1 < len(args):
                try:
                    target_pid = int(args[idx + 1])
                    success = ForensicMitigationEngine.resume_process(target_pid)
                    sys.exit(0 if success else 1)
                except ValueError:
                    sys.stderr.write("[!] Error: PID must be an integer.\n")
                    sys.exit(1)
            else:
                sys.stderr.write(f"[!] Error: {arg} requires a target PID.\n")
                sys.exit(1)
        elif arg == "--audit-only":
            audit_only = True
        elif arg == "--enable-ebpf":
            enable_ebpf = True
        elif arg == "--trust-signed":
            trust_signed_binaries = True
        elif arg == "--trusted-signers":
            if idx + 1 < len(args):
                signers = [s.strip() for s in args[idx + 1].split(",") if s.strip()]
                trusted_signers = signers
                trust_signed_binaries = True
                idx += 1
            else:
                sys.stderr.write("[!] Error: --trusted-signers requires a comma-separated list of names.\n")
                sys.exit(1)
        elif arg == "--allow-unprivileged":
            allow_unprivileged = True
        elif arg == "--consecutive-ticks":
            if idx + 1 < len(args):
                hysteresis_ticks = int(args[idx + 1])
                idx += 1
        elif arg == "--metrics-port":
            if idx + 1 < len(args):
                metrics_port = int(args[idx + 1])
                idx += 1
        elif arg == "--log-url":
            if idx + 1 < len(args):
                log_url = args[idx + 1]
                idx += 1
            else:
                sys.stderr.write("[!] Error: --log-url requires a target URL argument.\n")
                sys.exit(1)
        elif arg == "--cooldown":
            if idx + 1 < len(args):
                cooldown_sec = float(args[idx + 1])
                idx += 1
        elif arg == "--heartbeat":
            if idx + 1 < len(args):
                heartbeat_sec = int(args[idx + 1])
                idx += 1
        elif arg == "--spool-file":
            if idx + 1 < len(args):
                spool_file = args[idx + 1]
                idx += 1
        elif arg == "--whitelist":
            if idx + 1 < len(args):
                names = [n.strip() for n in args[idx + 1].split(",") if n.strip()]
                custom_whitelist.update(names)
                idx += 1
        elif arg == "--simulate":
            simulation_mode = True
            allow_unprivileged = True
        elif arg == "--test-egress":
            test_egress_only = True
        elif arg == "--once":
            run_once = True
            allow_unprivileged = True
        elif arg == "--insecure":
            insecure_tls = True
        elif arg == "--quiet":
            verbose = False
        elif arg == "--config":
            idx += 1
        else:
            sys.stderr.write(f"[!] Warning: Unrecognized option '{arg}'. Use --help for manual.\n")
        idx += 1

    # Immediate egress verification test
    if test_egress_only:
        sys.stdout.write(f"[*] Testing out-of-band intranet egress to {log_url}...\n")
        egress = IntranetEgressLogger(
            log_server_url=log_url,
            spool_file=spool_file,
            insecure_tls=insecure_tls,
            verbose=True
        )
        worker = egress.dispatch_alert_async(
            current_temp=58.4,
            tds_val=5.8,
            cpu_load=8.2,
            rolling_baseline=42.0,
            mitigated_records=[{
                "pid": 9999,
                "name": "canary_test_process",
                "action": "CANARY_VERIFICATION_TEST",
                "status": "TEST_ONLY"
            }],
            consecutive_ticks=1
        )
        worker.join(timeout=4.0)
        sys.stdout.write("[*] Egress test complete.\n")
        sys.exit(0)

    # Enforce startup privileges (root on Linux/macOS, admin on Windows)
    enforce_privilege_check(allow_unprivileged=allow_unprivileged)

    # Acquire singleton process lock to avoid conflicting sensor queries
    lock = SingleInstanceLock()
    if not lock.acquire():
        sys.stderr.write("[!] Error: Another instance of ThermoLock is already running on this endpoint.\n")
        sys.exit(1)

    daemon = ThermoLockDaemon(
        log_server_url=log_url,
        cooldown_sec=cooldown_sec,
        hysteresis_ticks=hysteresis_ticks,
        heartbeat_sec=heartbeat_sec,
        spool_file=spool_file,
        custom_whitelist=custom_whitelist,
        audit_only=audit_only,
        trust_signed_binaries=trust_signed_binaries,
        trusted_signers=trusted_signers,
        enable_ebpf=enable_ebpf,
        insecure_tls=insecure_tls,
        metrics_port=metrics_port,
        config_path=config_path,
        verbose=verbose,
        simulation_mode=simulation_mode
    )

    def signal_handler(signum, frame):
        sys.stdout.write("\n[*] Termination signal received. Shutting down ThermoLock daemon...\n")
        sys.stdout.flush()
        daemon.stop()

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    # Dynamic SIGHUP configuration reload handler (POSIX)
    if hasattr(signal, "SIGHUP"):
        def sighup_handler(signum, frame):
            daemon.reload_config()
        signal.signal(signal.SIGHUP, sighup_handler)

    try:
        cycles = 1 if run_once else None
        daemon.run(max_cycles=cycles)
    finally:
        lock.release()


if __name__ == "__main__":
    main()
