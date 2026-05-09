
```markdown
# 🔍 Memory Forensics Analyzer

> CET333 — Advanced Digital Forensics | Elsewedy University of Technology

![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python) ![Volatility3](https://img.shields.io/badge/Volatility3-Framework-green) ![YARA](https://img.shields.io/badge/YARA-Rules-red) ![PyQt5](https://img.shields.io/badge/PyQt5-GUI-purple) ![License](https://img.shields.io/badge/License-MIT-yellow)

A desktop memory forensics framework built with Python and PyQt5 that analyzes RAM dumps to detect malware, extract credentials, recover network connections, and identify attacker artifacts — before the system powers down.

---

## 👤 Author

| Field | Info |
|-------|------|
| Name | Mohamed Ahmed Gode |
| Student ID | 230102691 |
| Course | CET333 — Advanced Digital Forensics |
| University | Elsewedy University of Technology |
| Specialization | Cyber Security & Network |

---

## 📌 Problem Statement

Critical forensic evidence exists **only in RAM**. Running processes, encryption keys, active network connections, and malware artifacts vanish the moment a system powers down. Traditional disk forensics misses all of this. Memory forensics bridges that gap — but requires specialized tooling to capture and analyze volatile data quickly and accurately.

---

## 💡 Proposed Solution

A complete **Memory Forensics Framework** that:

- Parses memory dumps from Windows, Linux, and Mac systems
- Extracts running process trees with parent-child relationships
- Detects injected code and suspicious memory regions (malfind)
- Recovers active network sockets and connection tracking
- Extracts password hashes, LSA secrets, and cached credentials
- Scans memory with custom YARA rules for known malware signatures
- Presents all findings in a dark-themed interactive PyQt5 GUI

---

## 🛠 Tools & Technologies

| Tool | Version | Role |
|------|---------|------|
| **Volatility3** | v2.x | Core memory analysis engine |
| **Python** | 3.13 | Scripting, parsing, subprocess management |
| **YARA** | yara-python | Malware signature scanning |
| **PyQt5** | Latest | Interactive desktop GUI |

---

## 📁 Project Structure

```
Memory-Forensics-Analyzer/
│
├── main.py                    # Entry point — launches PyQt5 app
│
├── core/
│   ├── process_analyzer.py    # pslist, pstree, malfind, dlllist, cmdline
│   ├── network_analyzer.py    # netscan, netstat, connection tracking
│   ├── key_detector.py        # hashdump, lsadump, cachedump, cmdline audit
│   └── yara_scanner.py        # YARA rule compilation & memory scanning
│
├── gui/
│   └── viewer.py              # Main window, tabs, HTML rendering, zoom
│
├── yara_rules/
│   └── malware.yar            # Custom YARA detection rules
│
├── dumps/                     # Place your .raw / .vmem / .dmp files here
│
├── reports/                   # Auto-generated forensics reports (.txt)
│
└── requirements.txt
```

---

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/Eng-Mohamed-515/Memory-Forensics-Analyzer.git
cd Memory-Forensics-Analyzer
```

### 2. Install Python dependencies
```bash
pip install PyQt5 yara-python
```

### 3. Install Volatility3
```bash
pip install volatility3
```

### 4. Download a memory dump for testing

Sample dumps available at:
👉 https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples

Place the `.raw` file inside the `dumps/` folder.

### 5. Run the application
```bash
python main.py
```

---

## 🖥 Features

### ⚙ Process List
- Full pslist table with PID, PPID, Threads, Handles, Start Time
- Hierarchical pstree with ↳ parent-child indentation
- Color-coded: system processes (gray) vs interesting processes (blue)
- Showing 48 processes from the test dump

### 🌐 Network Analysis
- 242 active sockets recovered (UDP/TCP over IPv4 and IPv6)
- Protocol, Local Address, Foreign Address, State, PID, Owner
- Suspicious foreign IP flagging

### 🔑 Keys & Credentials
- Password hashes via `hashdump` (NT/LM format)
- LSA secrets via `lsadump`
- Cached credentials via `cachedump`
- Full command-line audit via `cmdline`

### 🔍 YARA Scan
- Custom `SuspiciousProcess` rule — detects MZ headers, shellcode API calls
- `SuspiciousNetworkActivity` rule — detects Tor, reverse shells
- Grouped results: rule name, matched strings, severity level

### 📊 Executive Summary
- Aggregated findings across all analysis modules
- KEY FORENSIC FINDINGS with severity tags (HIGH / MEDIUM / INFO)
- Risk Assessment bar (LOW / MEDIUM / HIGH)

---

## 📊 Sample Analysis Results (MemoryDump_Lab1.raw)

| Metric | Result |
|--------|--------|
| OS Profile | Windows XP/2003 |
| Total Processes | 48 |
| Network Connections | 242 |
| User Credentials Found | 5 |
| YARA Rules Triggered | 1 (SuspiciousProcess) |
| Risk Level | **HIGH** |

### 🔍 Key Forensic Findings

- **[HIGH]** `WinRAR.exe` (PID 1512) opened `Important.rar` from Alissa Simpson's Documents — possible data staging
- **[HIGH]** `malfind` detected `PAGE_EXECUTE_READWRITE` memory in 8 processes including `explorer.exe` and `svchost.exe`
- **[INFO]** `DumpIt.exe` (PID 796) under `SmartNet` account — confirms memory acquisition method
- **[MEDIUM]** Two `explorer.exe` instances (PID 604 & 2504) — dual user sessions detected
- **[INFO]** VirtualBox VM confirmed via `VBoxService.exe` and `VBoxTray.exe`

---

## 🎮 GUI Features

- Dark forensics theme (matching the tool's color scheme)
- 5 analysis tabs with filter/search bar
- Ctrl+Scroll / Ctrl+Plus/Minus zoom on all text areas
- Export full report to timestamped `.txt` file
- Real-time progress bar and status updates during analysis
- Live clock in top-right corner

---

## 📄 License

This project is submitted as part of CET333 — Advanced Digital Forensics coursework at Elsewedy University of Technology.
```

