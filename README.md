# ThermoLock EDR Engine Core 🛡️🔥

An enterprise-ready, bare-metal hardware Endpoint Detection & Response (EDR) agent and integration guard framework. **ThermoLock** detects advanced threats, ring -1 hypervisor rootkits, memory-only injections, and unlinked kernel-level implants by tracking physical silicon thermodynamic dissipation side-channels (Joule heating).

---

## ⚡ Architectural Concept

Advanced persistent threats frequently evade typical Operating System APIs through Direct Kernel Object Manipulation (DKOM) or runtime hook bypassing. However, execution requires current consumption across CMOS physical silicon gates:

\[\text{P}_{\text{dynamic}} = \alpha \cdot \text{C} \cdot \text{V}^2 \cdot f + \text{I}_{\text{leakage}} \cdot \text{V}\]

Malware running intensive background computations (e.g., memory compression, cryptojacking, stealth scanning) generates physical thermal shifts. ThermoLock measures the **Thermal Delta Speed (TDS)** at regular 1.0-second intervals out-of-band to catch execution anomalies before they match standard OS accounting loops.

### 📌 Anomaly Logic Gate
A threat anomaly is flagged when:
1. **Thermal Delta Speed (TDS)** ≥ 5.0°C/s
2. **Global OS CPU Load** ≤ 15.0%
3. The condition satisfies a multi-sample **hysteresis filter** (default: 3 continuous samples).

---

## 🚀 Sensor Agent Component (`thermolock_agent.py`)

The standalone endpoint runtime features an optimized, zero-process-churn collection mechanism across Linux, Windows, and macOS architectures.

### Key Capabilities
* **Ring 0 Telemetry Bridge:** Integrates a native Linux eBPF scheduler probe via BCC tracking context switch runtime durations directly out of kernel space (`tracepoint:sched:sched_switch`).
* **Forensic-Safe Mitigations:** Freezes rogue processes via `SIGSTOP` (Linux), traps allocations onto Core 0 via Win32 processor affinity shifts (Windows), or executes nice priority restrictions (macOS) to arrest power consumption while fully preserving volatile RAM layouts for live memory capture.
* **Resilient Intranet Egress:** Locally spools events to a bounded 10MB FIFO disk queue with randomized exponential network retry structures to withstand connectivity drops.

### Operational Commands
```bash
# Execute standard telemetry daemon monitor loop
sudo python3 thermolock_agent.py

# Run in validation mode injecting an artificial anomaly spike
python3 thermolock_agent.py --simulate

# Run system sensor discovery diagnostics
sudo python3 thermolock_agent.py --check-sensors

# Generate a hardened, production-ready systemd configuration unit
python3 thermolock_agent.py --print-systemd

# Unfreeze / resume a previously mitigated process ID during Incident Response
sudo python3 thermolock_agent.py --resume <PID>
```

---

## 🧪 Verification & Gate Guard Component (`thermolock_guard.py`)

A comprehensive standard-library test suite, intake verification engine, and regression ledger wrapper validating software updates and analysis reports.

### Key Capabilities
* **4-Gate Verification Path:** Asserts hash anchoring authenticity, flags square-bracket extraction defects (`BRACKET_EATEN`), checks reproductive fault conditions, and filters findings against historical adjudicated ledger logs.
* **Integrated Check Engine:** Validates runtime stability configurations dynamically over an inline 24-check regression battery.

### Operational Commands
```bash
# Run the complete inline 24-check regression suite
python3 thermolock_guard.py suite

# Run the verification engine against a targeted assessment structure
python3 thermolock_guard.py verify path/to/review.json

# Execute intake behavior safety self-testing protocols
python3 thermolock_guard.py selftest

# Review current elements recorded across the internal ledger registry
python3 thermolock_guard.py ledger list
```

---

## 🛡️ Hardening Strategy & Fleet Deployment

To scale fleet coverage, dump the target unit profile output right into your system configuration hierarchy:

```bash
sudo python3 thermolock_agent.py --print-systemd > /etc/systemd/system/thermolock.service
sudo systemctl daemon-reload
sudo systemctl enable --now thermolock
```
