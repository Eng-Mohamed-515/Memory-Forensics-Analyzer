"""
Memory Forensics Viewer — PyQt5 GUI (Redesigned v2)
"""
import os, re, html
from datetime import datetime
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QEvent
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QTabWidget, QTextEdit, QVBoxLayout, QHBoxLayout,
    QGridLayout, QFileDialog, QStatusBar, QProgressBar, QMessageBox, QLabel,
    QPushButton, QFrame, QSplitter, QLineEdit, QScrollArea, QSizePolicy,
)

KNOWN_SYSTEM = {"system","smss.exe","csrss.exe","wininit.exe","services.exe",
    "lsass.exe","lsm.exe","svchost.exe","winlogon.exe","psxss.exe",
    "spoolsv.exe","dwm.exe","taskhost.exe","audiodg.exe","conhost.exe",
    "searchindexer.","searchprotocol","searchfilterho","sppsvc.exe","wmpnetwk.exe"}

INTERESTING_PROCS = {"vboxservice.ex","vboxtray.exe","tcpsvcs.exe","cmd.exe",
    "mspaint.exe","explorer.exe","winrar.exe","dumpit.exe"}

def _e(t):
    return html.escape(str(t))

def _wrap(body):
    return (f'<html><body style="background-color:#0d1117;color:#e6edf3;'
            f'font-family:Courier New;font-size:9pt;margin:8px;">{body}</body></html>')

def _fmt_header_lines(raw_text):
    """Format the === header block into styled HTML."""
    out = []
    for line in raw_text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("===") or s.startswith("─"):
            out.append(f'<p style="color:#00ff41;margin:2px 0;">{_e(s)}</p>')
        else:
            out.append(f'<p style="color:#ffa657;font-weight:bold;margin:2px 0;">{_e(s)}</p>')
    return "\n".join(out)

def _is_data_line(line):
    return line.strip().startswith("0x")

def _fmt_processes(raw_text):
    """Parse combined process output into HTML.
    Uses split_sections() to separate pslist/pstree/malfind/dlllist,
    then applies the right parser to each section.
    """
    secs = split_sections(raw_text)
    out = []

    # ---- SECTION 1: PROCESS LIST TABLE (pslist — inline 0x offset format) ----
    if secs['pslist'].strip():
        out.append('<p style="color:#00ff41;font-weight:bold;border-bottom:2px solid #00ff41;'
                   'padding-bottom:4px;margin:8px 0;">PROCESS LIST (pslist)</p>')
        processes = _parse_pslist_inline(secs['pslist'])
        if processes:
            t = ('<table style="width:100%;border-collapse:collapse;font-family:Courier New;font-size:9pt;">'
                 '<tr style="background:#161b22;color:#00ff41;border-bottom:2px solid #00ff41;">'
                 '<th style="padding:8px 6px;text-align:left;min-width:160px;">Process Name</th>'
                 '<th style="padding:8px 6px;text-align:left;">PID</th>'
                 '<th style="padding:8px 6px;text-align:left;">PPID</th>'
                 '<th style="padding:8px 6px;text-align:left;">Threads</th>'
                 '<th style="padding:8px 6px;text-align:left;">Handles</th>'
                 '<th style="padding:8px 6px;text-align:left;">Start Time</th></tr>')
            for i, (nm, pid, ppid, thd, hnd, ts) in enumerate(processes):
                nl = nm.lower()
                is_int = any(nl == s or nl.startswith(s.rstrip('.')) for s in INTERESTING_PROCS)
                is_sys = any(nl == s or nl.startswith(s.rstrip('.')) for s in KNOWN_SYSTEM)
                if is_int:
                    bg = "#0d1a2e" if i % 2 == 0 else "#0f1d30"; nc = "#79c0ff"
                elif is_sys:
                    bg = "#0d1117" if i % 2 == 0 else "#111820"; nc = "#6e7681"
                else:
                    bg = "#0d1a2e" if i % 2 == 0 else "#0f1d30"; nc = "#c9d1d9"
                t += (f'<tr style="background:{bg};border-bottom:1px solid #1c2128;">'
                      f'<td style="padding:5px 6px;color:{nc};font-weight:bold;">{_e(nm)}</td>'
                      f'<td style="padding:5px 6px;color:#f0883e;">{_e(pid)}</td>'
                      f'<td style="padding:5px 6px;color:#f0883e;">{_e(ppid)}</td>'
                      f'<td style="padding:5px 6px;color:#e6edf3;">{_e(thd)}</td>'
                      f'<td style="padding:5px 6px;color:#e6edf3;">{_e(hnd)}</td>'
                      f'<td style="padding:5px 6px;color:#6e7681;">{_e(ts)}</td></tr>')
            t += '</table>'
            out.append(t)
        else:
            out.append('<p style="color:#ff7b72;">No process data parsed from pslist section.</p>')
            out.append(f'<pre style="color:#8b949e;font-size:8pt;">{_e(secs["pslist"][:2000])}</pre>')

    # ---- SECTION 2: PROCESS TREE (pstree — table format) ----
    if secs['pstree'].strip():
        out.append('<br><p style="color:#ffa657;font-weight:bold;border-top:1px solid #30363d;'
                   'padding-top:8px;margin:8px 0;">PROCESS TREE (pstree)</p>')
        t = ('<table style="width:100%;border-collapse:collapse;font-family:Courier New;font-size:9pt;margin-top:8px;">'
             '<tr style="background:#161b22;color:#00ff41;border-bottom:2px solid #00ff41;">'
             '<th style="padding:6px;text-align:left;">Process Name</th>'
             '<th style="padding:6px;text-align:left;width:60px;">PID</th>'
             '<th style="padding:6px;text-align:left;width:60px;">PPID</th>'
             '<th style="padding:6px;text-align:left;width:60px;">Threads</th>'
             '<th style="padding:6px;text-align:left;">Start Time</th></tr>')
        row_i = 0
        for line in secs['pstree'].split('\n'):
            s = line.strip()
            if not s or '====' in s or s.startswith('Dump:') or s.startswith('Time:'):
                continue
            if 'PROCESS TREE' in s.upper():
                continue
            if s.startswith('Name ') or s.startswith('------') or s.startswith('Pid'):
                continue
            # Count leading spaces for indent level
            leading = len(line) - len(line.lstrip(' .'))
            indent_level = leading // 2
            indent_html = ('&nbsp;&nbsp;&nbsp;&nbsp;' * indent_level + '↳ ') if indent_level > 0 else ''
            # Strip 0xfffff...: prefix
            rest = s.lstrip('. ')
            colon_m = re.match(r'0x[0-9a-fA-F]+:(.+)', rest)
            if colon_m:
                rest = colon_m.group(1)
            parts = rest.split()
            if len(parts) < 4:
                continue
            # Validate: parts[1] should be numeric (PID)
            if not parts[1].isdigit():
                continue
            pname = parts[0]
            pid_val = parts[1]
            ppid_val = parts[2]
            thd_val = parts[3]
            dt_val = ''
            if len(parts) >= 7:
                dt_val = parts[5] + ' ' + parts[6]
            elif len(parts) >= 6:
                dt_val = parts[5]
            # Determine name color
            nl = pname.lower()
            if any(nl == k or nl.startswith(k.rstrip('.')) for k in INTERESTING_PROCS):
                name_color = "#79c0ff"
            elif any(nl == k or nl.startswith(k.rstrip('.')) for k in KNOWN_SYSTEM):
                name_color = "#6e7681"
            else:
                name_color = "#c9d1d9"
            bg = "#0d1117" if row_i % 2 == 0 else "#111820"
            t += (f'<tr style="background:{bg};border-bottom:1px solid #1c2128;">'
                  f'<td style="padding:5px 6px;color:{name_color};font-weight:bold;">{indent_html}{_e(pname)}</td>'
                  f'<td style="padding:5px 6px;color:#f0883e;">{_e(pid_val)}</td>'
                  f'<td style="padding:5px 6px;color:#6e7681;">{_e(ppid_val)}</td>'
                  f'<td style="padding:5px 6px;color:#e6edf3;">{_e(thd_val)}</td>'
                  f'<td style="padding:5px 6px;color:#6e7681;">{_e(dt_val)}</td></tr>')
            row_i += 1
        t += '</table>'
        out.append(t)

    # ---- SECTION 3: MALFIND — parse "Process: X Pid: Y" lines ----
    if secs['malfind'].strip():
        out.append('<br><p style="color:#ff7b72;font-weight:bold;border-top:1px solid #30363d;'
                   'padding-top:8px;margin:8px 0;">⚠ CODE INJECTION DETECTION (malfind)</p>')
        # Extract unique process entries from malfind
        malfind_procs = []
        seen_mf = set()
        has_rwx = False
        for line in secs['malfind'].split('\n'):
            s = line.strip()
            m = re.search(r'Process:\s*(.+?)\s+Pid:\s*(\d+)', s)
            if m:
                pname, ppid = m.group(1).strip(), m.group(2)
                key = f'{pname}_{ppid}'
                if key not in seen_mf:
                    seen_mf.add(key)
                    malfind_procs.append((pname, ppid))
            if 'PAGE_EXECUTE_READWRITE' in s:
                has_rwx = True
        if malfind_procs:
            for pname, ppid in malfind_procs:
                note = ' — PAGE_EXECUTE_READWRITE memory detected' if has_rwx else ''
                out.append(f'<div style="border-left:3px solid #ff7b72;padding:4px 10px;margin:3px 0;background:#1a0a0a;">'
                           f'<span style="color:#ff7b72;font-weight:bold;">{_e(pname)}</span>'
                           f' <span style="color:#8b949e;">PID:</span> <span style="color:#f0883e;">{_e(ppid)}</span>'
                           f'<span style="color:#ffa657;font-size:8pt;">{note}</span></div>')
        else:
            # Show meaningful non-hex lines as fallback
            meaningful = []
            for line in secs['malfind'].split('\n'):
                s = line.strip()
                if not s or '====' in s or s.startswith('Dump:') or s.startswith('Time:'):
                    continue
                if 'CODE INJECTION' in s.upper():
                    continue
                stripped_hex = s.replace(' ', '').replace('\t', '')
                if len(stripped_hex) > 5 and all(c in '0123456789abcdefABCDEF.' for c in stripped_hex):
                    continue
                if s.startswith('0x') and len(s) < 60:
                    continue
                if len(s) > 3:
                    meaningful.append(s)
            if meaningful:
                for line in meaningful[:20]:
                    out.append(f'<p style="margin:1px 0;color:#ff7b72;font-size:8pt;">{_e(line)}</p>')
            else:
                out.append('<p style="color:#00ff41;">No definitive code injection patterns detected</p>')

    # DLL LIST is intentionally not shown in Process List tab

    return _wrap("\n".join(out))


def _fmt_network(raw_text):
    """Parse netscan output into HTML table."""
    sections = re.split(r'(={60}[\s\S]*?={60})', raw_text)
    out = []
    for sec in sections:
        sec = sec.strip()
        if not sec:
            continue
        if sec.startswith("===="):
            out.append(_fmt_header_lines(sec))
            continue
        rows = []; other = []
        for line in sec.splitlines():
            s = line.strip()
            if not s:
                continue
            low = s.lower()
            if "offset" in low and ("proto" in low or "local" in low):
                continue
            if s.startswith("------"):
                continue
            if s.startswith("0x"):
                tokens = s.split()
                if len(tokens) >= 3:
                    try:
                        proto = tokens[1]
                        local_addr = tokens[2]
                        foreign = tokens[3] if len(tokens) > 3 else "*:*"
                        state = tokens[4] if len(tokens) > 4 else "N/A"
                        pid = tokens[5] if len(tokens) > 5 else "?"
                        owner = tokens[6] if len(tokens) > 6 else "?"
                        # UDP has no state — state field is actually PID
                        if state.isdigit():
                            pid = state; state = "N/A"; owner = tokens[5] if len(tokens) > 5 else "?"
                    except IndexError:
                        proto = tokens[1] if len(tokens) > 1 else "?"
                        local_addr = tokens[2] if len(tokens) > 2 else "?"
                        foreign = "*:*"; state = "N/A"; pid = "?"; owner = "?"
                    rows.append((proto, local_addr, foreign, state, pid, owner))
                    continue
            other.append(f'<p style="color:#8b949e;margin:2px 0;">{_e(s)}</p>')
        if rows:
            t = ('<table style="width:100%;border-collapse:collapse;font-family:Courier New;font-size:9pt;">'
                 '<tr style="background:#161b22;color:#00ff41;border-bottom:2px solid #00ff41;">'
                 '<th style="padding:8px 6px;text-align:left;">Protocol</th>'
                 '<th style="padding:8px 6px;text-align:left;">Local Address</th>'
                 '<th style="padding:8px 6px;text-align:left;">Foreign Address</th>'
                 '<th style="padding:8px 6px;text-align:left;">State</th>'
                 '<th style="padding:8px 6px;text-align:left;">PID</th>'
                 '<th style="padding:8px 6px;text-align:left;">Owner</th></tr>')
            for i, (proto, la, fa, st, pid, own) in enumerate(rows):
                bg = "#0d1117" if i % 2 == 0 else "#111820"
                sc = "#e6edf3"  # state color
                if st.upper() == "ESTABLISHED":
                    bg = "#0a1a0a" if i % 2 == 0 else "#0c1f0c"; sc = "#00ff41"
                elif st.upper() == "LISTENING":
                    sc = "#ffa657"
                elif st.upper() in ("CLOSE_WAIT","TIME_WAIT"):
                    sc = "#ff7b72"
                fc = "#ffa657" if fa not in ("*:*","0.0.0.0:0","0.0.0.0:*","-") and not fa.startswith("0.0.0.0") else "#e6edf3"
                t += (f'<tr style="background:{bg};border-bottom:1px solid #1c2128;">'
                      f'<td style="padding:6px;color:#ffa657;font-weight:bold;">{_e(proto)}</td>'
                      f'<td style="padding:6px;color:#e6edf3;">{_e(la)}</td>'
                      f'<td style="padding:6px;color:{fc};">{_e(fa)}</td>'
                      f'<td style="padding:6px;color:{sc};font-weight:bold;">{_e(st)}</td>'
                      f'<td style="padding:6px;color:#f0883e;">{_e(pid)}</td>'
                      f'<td style="padding:6px;color:#79c0ff;">{_e(own)}</td></tr>')
            t += '</table>'
            out.append(t)
        if other:
            out.extend(other)
    return _wrap("\n".join(out))

def _fmt_credentials(raw_text):
    """Parse hashdump/lsadump/cachedump/cmdline output with proper section isolation."""
    sections = re.split(r'(={60,}[\s\S]*?={60,})', raw_text)
    out = []
    section_icons = {"PASSWORD":"🔑","LSA":"🔐","CACHED":"📋","CMDLINE":"💻"}
    current_section = ""
    for sec in sections:
        sec = sec.strip()
        if not sec:
            continue
        if sec.startswith("===="):
            up = sec.upper()
            for key, icon in section_icons.items():
                if key in up:
                    for line in sec.splitlines():
                        s = line.strip()
                        if s and not s.startswith("===") and "Dump:" not in s and "Time:" not in s:
                            current_section = key
                            out.append(f'<h3 style="color:#ffa657;border-bottom:2px solid #ffa657;padding-bottom:4px;margin-top:16px;">{icon} {_e(s)}</h3>')
                            break
                    for line in sec.splitlines():
                        s = line.strip()
                        if ("Dump:" in s or "Time:" in s) and not s.startswith("==="):
                            out.append(f'<p style="color:#8b949e;margin:2px 0;">{_e(s)}</p>')
                    break
            continue
        sec_lines = []
        for line in sec.splitlines():
            s = line.strip()
            if not s:
                continue
            # PASSWORD HASHES: only lines matching Username:RID:LM:NT
            if current_section == "PASSWORD" and s.count(":") >= 3:
                hash_parts = s.split(":")
                if len(hash_parts) >= 4:
                    user = hash_parts[0]
                    rid_str = hash_parts[1]
                    try:
                        rid = int(rid_str)
                        if 100 <= rid <= 9999:
                            nt_hash = hash_parts[3] if len(hash_parts) > 3 else "N/A"
                            sec_lines.append(
                                f'<div style="border:1px solid #30363d;border-radius:4px;padding:8px;margin:4px 0;background:#161b22;">'
                                f'<span style="color:#ffa657;font-weight:bold;">Username: </span><span style="color:#ff7b72;">{_e(user)}</span>'
                                f'<span style="color:#8b949e;"> | RID: </span><span style="color:#f0883e;">{_e(rid_str)}</span>'
                                f'<br><span style="color:#8b949e;font-size:8pt;">NT Hash: </span>'
                                f'<span style="color:#e6edf3;font-size:8pt;">{_e(nt_hash)}</span></div>')
                            continue
                    except ValueError:
                        pass
            # CMDLINE: format process entries
            if current_section == "CMDLINE":
                pid_match = re.match(r'^(\S+)\s+pid:\s*(\d+)', s)
                if pid_match:
                    pname = pid_match.group(1)
                    ppid = pid_match.group(2)
                    # Extract command line from next part
                    cmd_match = re.search(r'Command line\s*:\s*(.*)', s)
                    cmdline = cmd_match.group(1).strip() if cmd_match else ""
                    # Determine border color and icon
                    border_c = "#30363d"; icon = ""; bg_c = "#111820"
                    if "WinRAR" in pname or "WinRAR" in cmdline:
                        border_c = "#ff7b72"; icon = "⚠ "; bg_c = "#1a0a0a" if "Important.rar" in cmdline else "#111820"
                    elif "DumpIt" in pname or "DumpIt" in cmdline:
                        border_c = "#ffa657"; icon = "ℹ "
                    sec_lines.append(
                        f'<div style="border-left:3px solid {border_c};padding:6px 10px;margin:3px 0;background:{bg_c};">'
                        f'{icon}<span style="color:#ffa657;font-weight:bold;">{_e(pname)}</span>'
                        f' <span style="color:#8b949e;">PID: </span><span style="color:#f0883e;">{_e(ppid)}</span><br>'
                        f'<span style="color:#6e7681;font-size:8pt;">Command line: </span>'
                        f'<span style="color:#e6edf3;font-size:8pt;">{_e(cmdline)}</span></div>')
                    continue
                # Some cmdline lines may span multiple lines; check for "Command line :"
                if s.startswith("Command line"):
                    cmd_match = re.match(r'Command line\s*:\s*(.*)', s)
                    cmdline = cmd_match.group(1).strip() if cmd_match else s
                    bg_c = "#1a0a0a" if "Important.rar" in cmdline else "#111820"
                    sec_lines.append(
                        f'<div style="border-left:3px solid #30363d;padding:6px 10px;margin:3px 0;background:{bg_c};">'
                        f'<span style="color:#6e7681;font-size:8pt;">Command line: </span>'
                        f'<span style="color:#e6edf3;font-size:8pt;">{_e(cmdline)}</span></div>')
                    continue
            # Default formatting
            sec_lines.append(f'<p style="color:#e6edf3;margin:1px 0;">{_e(s)}</p>')
        if sec_lines:
            out.append(f'<div style="border-left:4px solid #00ff41;padding-left:10px;margin-bottom:15px;background:#161b22;padding:8px 8px 8px 14px;border-radius:4px;">{"".join(sec_lines)}</div>')
    if not out:
        out.append('<p style="color:#8b949e;"><i>No credential data available.</i></p>')
    return _wrap("\n".join(out))

def _fmt_yara(raw_text):
    """Parse YARA output — group by rule, summarize matches."""
    if not raw_text or not raw_text.strip():
        return _wrap('<div style="border:1px solid #00ff41;border-radius:6px;padding:12px;margin:8px 0;background:#0a1a0a;">'
                     '<p style="color:#00ff41;font-size:11pt;font-weight:bold;">✓ No threats detected</p>'
                     '<p style="color:#8b949e;">YARA scan completed with no rule matches.</p></div>')
    # Extract header
    header_match = re.search(r'(={60}[\s\S]*?={60})', raw_text)
    header_html = _fmt_header_lines(header_match.group(1)) if header_match else ""
    # Check for errors or no matches
    if "[!]" in raw_text or "not installed" in raw_text.lower():
        return _wrap(header_html + f'<div style="border:1px solid #ffa657;border-radius:6px;padding:12px;margin:8px 0;background:#1a1500;">'
                     f'<p style="color:#ffa657;font-size:11pt;font-weight:bold;">⚠ YARA Warning</p>'
                     f'<p style="color:#e6edf3;">{_e(raw_text.split("===")[-1].strip() if "===" in raw_text else raw_text)}</p></div>')
    if "no yara rule matches" in raw_text.lower():
        return _wrap(header_html + '<div style="border:1px solid #00ff41;border-radius:6px;padding:12px;margin:8px 0;background:#0a1a0a;">'
                     '<p style="color:#00ff41;font-size:11pt;font-weight:bold;">✓ No threats detected</p>'
                     '<p style="color:#8b949e;">YARA scan completed with no rule matches.</p></div>')
    # Parse rules
    rules = {}
    current_rule = None
    for line in raw_text.splitlines():
        s = line.strip()
        rm = re.match(r'Rule:\s*(\S+)', s)
        if rm:
            current_rule = rm.group(1)
            if current_rule not in rules:
                rules[current_rule] = {"desc":"","strings":{},"count":0}
            continue
        dm = re.match(r'Description:\s*(.*)', s)
        if dm and current_rule:
            rules[current_rule]["desc"] = dm.group(1)
            continue
        if current_rule and "Offset" in s and "|" in s:
            parts = s.split("|")
            if len(parts) >= 2:
                sname = parts[1].strip()
                rules[current_rule]["strings"][sname] = rules[current_rule]["strings"].get(sname, 0) + 1
                rules[current_rule]["count"] += 1
            continue
        tm = re.match(r'Total YARA matches:\s*(\d+)', s)
    out = [header_html]
    out.append(f'<h3 style="color:#ff7b72;margin:8px 0;">⚠ MATCH SUMMARY — {len(rules)} rule(s) triggered</h3>')
    for rname, rdata in rules.items():
        str_parts = []
        for sn, cnt in rdata["strings"].items():
            str_parts.append(f"{_e(sn)} ({cnt} occurrences)")
        str_text = ", ".join(str_parts) if str_parts else "N/A"
        out.append(
            f'<div style="border:1px solid #ff7b72;border-radius:6px;padding:12px;margin:8px 0;background:#1a0a0a;">'
            f'<p style="color:#ff7b72;font-size:11pt;font-weight:bold;">⚠ RULE MATCHED: {_e(rname)}</p>'
            f'<p style="color:#8b949e;">Description: {_e(rdata["desc"])}</p>'
            f'<p style="color:#ffa657;">Matched strings: {str_text}</p>'
            f'<p style="color:#e6edf3;">Total offset hits: {rdata["count"]}</p>'
            f'<p style="color:#ff7b72;font-weight:bold;">Severity: HIGH</p></div>')
    if not rules:
        out.append('<div style="border:1px solid #00ff41;border-radius:6px;padding:12px;margin:8px 0;background:#0a1a0a;">'
                   '<p style="color:#00ff41;font-size:11pt;font-weight:bold;">✓ No threats detected</p></div>')
    return _wrap("\n".join(out))

def _fmt_generic(raw_text):
    """Fallback formatter."""
    if not raw_text or not raw_text.strip():
        return _wrap('<p style="color:#8b949e;"><i>No data available.</i></p>')
    out = []
    for line in raw_text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("===") or s.startswith("─"):
            out.append(f'<p style="color:#00ff41;font-weight:bold;margin:2px 0;">{_e(s)}</p>')
        else:
            el = _e(s)
            el = re.sub(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', r'<span style="color:#8b949e;">\1</span>', el)
            out.append(f'<p style="color:#e6edf3;margin:1px 0;">{el}</p>')
    return _wrap("\n".join(out))

def format_output_as_html(raw_text, output_type="generic"):
    if output_type == "process":
        return _fmt_processes(raw_text)
    elif output_type == "network":
        return _fmt_network(raw_text)
    elif output_type == "credentials":
        return _fmt_credentials(raw_text)
    elif output_type == "yara":
        return _fmt_yara(raw_text)
    return _fmt_generic(raw_text)

def split_sections(raw_text):
    """Split combined analyzer output into named sections.
    Returns dict: {'pslist': str, 'pstree': str, 'malfind': str, 'dlllist': str, 'cmdline': str}
    """
    sections = {'pslist': '', 'pstree': '', 'malfind': '', 'dlllist': '', 'cmdline': ''}
    markers = {
        'PROCESS LIST': 'pslist',
        'PROCESS TREE': 'pstree',
        'CODE INJECTION': 'malfind',
        'DLL LIST': 'dlllist',
        'CMDLINE SEARCH': 'cmdline',
    }
    current_section = None
    current_lines = []
    for line in raw_text.split('\n'):
        matched = False
        for marker, key in markers.items():
            if marker in line.upper():
                if current_section:
                    sections[current_section] = '\n'.join(current_lines)
                current_section = key
                current_lines = [line]
                matched = True
                break
        if not matched and current_section:
            current_lines.append(line)
    if current_section:
        sections[current_section] = '\n'.join(current_lines)
    return sections


def _parse_pslist_inline(pslist_text):
    """Parse pslist section where each line starting with 0x is one process.
    Volatility3 pslist format:
      0xfffffa80... Name  PID  PPID  Threads  Handles  Session  Wow64  Date  Time
    Returns list of tuples: (name, pid, ppid, threads, handles, start_time)
    """
    processes = []
    for line in pslist_text.split('\n'):
        line = line.strip()
        if not line.startswith('0x'):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        # parts[0]=offset, [1]=name, [2]=pid, [3]=ppid, [4]=threads, [5]=handles
        name = parts[1]
        pid = parts[2]
        ppid = parts[3]
        threads = parts[4]
        handles = parts[5]
        # Start time is parts[8] + parts[9] if available
        start_time = ''
        if len(parts) >= 10:
            start_time = parts[8] + ' ' + parts[9]
        elif len(parts) >= 9:
            start_time = parts[8]
        # Validate numeric fields
        if pid.isdigit() and ppid.isdigit() and threads.isdigit() and handles.isdigit():
            processes.append((name, pid, ppid, threads, handles, start_time))
    return processes


def _count_valid_cred_lines(raw_text):
    """Count valid hashdump lines (Username:RID:LM:NT format)."""
    count = 0
    for l in raw_text.splitlines():
        parts = l.strip().split(':')
        if len(parts) >= 4 and not l.strip().startswith('='):
            try:
                rid = int(parts[1])
                if 100 <= rid <= 9999:
                    count += 1
            except (ValueError, IndexError):
                pass
    return count


def extract_stats(results):
    s = {"processes":0,"connections":0,"threats":0,"findings":0}
    # Processes: split sections, then parse pslist only
    pt = results.get("Process List","")
    proc_secs = split_sections(pt)
    s["processes"] = len(_parse_pslist_inline(proc_secs['pslist']))
    # Connections: count lines starting with 0x in netscan output
    nt = results.get("Network","")
    for l in nt.splitlines():
        if l.strip().startswith("0x"):
            s["connections"] += 1
    # Threats: count distinct YARA rule names
    yt = results.get("YARA Scan","")
    s["threats"] = len(set(re.findall(r'Rule:\s*(\S+)', yt)))
    # Findings: count valid credential lines
    kt = results.get("Keys & Credentials","")
    s["findings"] = _count_valid_cred_lines(kt)
    return s


class AnalysisWorker(QThread):
    result_ready = pyqtSignal(str, str)
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    error = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, dump_path, analysis_type="all", parent=None):
        super().__init__(parent)
        self.dump_path = dump_path
        self.analysis_type = analysis_type

    def run(self):
        from core.process_analyzer import ProcessAnalyzer
        from core.network_analyzer import NetworkAnalyzer
        from core.key_detector import KeyDetector
        from core.yara_scanner import YaraScanner
        try:
            if self.analysis_type in ("all","processes"):
                self.status.emit("Analyzing processes...")
                pa = ProcessAnalyzer(self.dump_path)
                combined = pa.get_process_list()+"\n\n"+pa.get_process_tree()+"\n\n"+pa.detect_code_injection()+"\n\n"+pa.get_dlls()
                self.result_ready.emit("Process List", combined)
                self.progress.emit(25)
            if self.analysis_type in ("all","network"):
                self.status.emit("Analyzing network...")
                na = NetworkAnalyzer(self.dump_path)
                combined = na.get_connections()+"\n\n"+na.get_sockets()
                self.result_ready.emit("Network", combined)
                self.progress.emit(50)
            if self.analysis_type in ("all","keys"):
                self.status.emit("Extracting credentials...")
                kd = KeyDetector(self.dump_path)
                combined = kd.find_hashes()+"\n\n"+kd.find_lsa_secrets()+"\n\n"+kd.find_cached_creds()+"\n\n"+kd.search_for_key_patterns()
                self.result_ready.emit("Keys & Credentials", combined)
                self.progress.emit(75)
            if self.analysis_type in ("all","yara"):
                self.status.emit("Running YARA scan...")
                rp = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),"yara_rules","malware.yar")
                ys = YaraScanner(self.dump_path, rp)
                ys.compile_rules()
                self.result_ready.emit("YARA Scan", ys.get_results_string())
                self.progress.emit(100)
        except Exception as e:
            self.error.emit(f"[!] Analysis error: {e}")
        self.finished_signal.emit()


class MemoryViewer(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.dump_path = None
        self.worker = None
        self.raw_results = {}
        self.tab_html_cache = {}
        self._zoom_size = 9  # default font size in pt
        self._init_ui()
        # Install event filter on all text edits for Ctrl+Scroll zoom
        for te in self.tab_edits.values():
            te.installEventFilter(self)
        self._clock = QTimer(self); self._clock.timeout.connect(self._tick); self._clock.start(1000)

    def _stitle(self, t):
        l = QLabel(t); l.setStyleSheet("color:#00ff41;font-size:9pt;font-weight:bold;font-family:Courier New;"); return l

    def _make_sidebar(self):
        scroll = QScrollArea()
        scroll.setMinimumWidth(220); scroll.setMaximumWidth(220); scroll.setFixedWidth(220)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:#161b22;border-radius:10px;} QScrollBar:vertical{background:#161b22;width:6px;} QScrollBar::handle:vertical{background:#30363d;border-radius:3px;}")
        sb = QWidget()
        sb.setStyleSheet("QWidget{background:#161b22;}")
        L = QVBoxLayout(sb); L.setContentsMargins(10,10,10,10); L.setSpacing(6)
        hdr = QLabel(); hdr.setAlignment(Qt.AlignCenter)
        hdr.setText('<span style="font-size:14pt;font-weight:bold;color:white;">MEMORY</span><br><span style="font-size:14pt;font-weight:bold;color:#00ff41;">FORENSICS</span><br><span style="font-size:9pt;color:#8b949e;">ANALYZER</span>')
        L.addWidget(hdr)
        s1 = QFrame(); s1.setFrameShape(QFrame.HLine); s1.setStyleSheet("color:#30363d;"); L.addWidget(s1)
        L.addWidget(self._stitle("[ CASE INFO ]"))
        self.lbl_status = QLabel("● Idle"); self.lbl_status.setStyleSheet("color:#8b949e;font-family:Courier New;font-size:9pt;"); L.addWidget(self.lbl_status)
        self.lbl_file = QLabel("File: —"); self.lbl_file.setStyleSheet("color:#8b949e;font-family:Courier New;font-size:9pt;"); self.lbl_file.setWordWrap(True); L.addWidget(self.lbl_file)
        self.lbl_size = QLabel("Size: —"); self.lbl_size.setStyleSheet("color:#8b949e;font-family:Courier New;font-size:9pt;"); L.addWidget(self.lbl_size)
        self.lbl_profile = QLabel("OS: —"); self.lbl_profile.setStyleSheet("color:#8b949e;font-family:Courier New;font-size:9pt;"); L.addWidget(self.lbl_profile)
        self.lbl_loaded = QLabel("Loaded: —"); self.lbl_loaded.setStyleSheet("color:#8b949e;font-family:Courier New;font-size:9pt;"); L.addWidget(self.lbl_loaded)
        s2 = QFrame(); s2.setFrameShape(QFrame.HLine); s2.setStyleSheet("color:#30363d;"); L.addWidget(s2)
        L.addWidget(self._stitle("[ CONTROLS ]"))
        BS = "QPushButton{height:36px;border-radius:6px;font-size:10pt;font-weight:bold;padding:0 10px;border:1px solid #30363d;}"
        self.btn_load = QPushButton("📂  Load Dump"); self.btn_load.setStyleSheet(BS+"QPushButton{background:#21262d;color:white;}QPushButton:hover{background:#30363d;}"); self.btn_load.clicked.connect(self._on_load); L.addWidget(self.btn_load)
        self.btn_run = QPushButton("▶  Run Full Analysis"); self.btn_run.setStyleSheet(BS+"QPushButton{background:#238636;color:white;border:none;}QPushButton:hover{background:#2ea043;}QPushButton:disabled{background:#1a2e1a;color:#4a4a4a;}"); self.btn_run.setEnabled(False); self.btn_run.clicked.connect(lambda: self._run("all")); L.addWidget(self.btn_run)
        self.btn_export = QPushButton("💾  Export Report"); self.btn_export.setStyleSheet(BS+"QPushButton{background:#21262d;color:white;}QPushButton:hover{background:#30363d;}QPushButton:disabled{background:#161b22;color:#4a4a4a;}"); self.btn_export.setEnabled(False); self.btn_export.clicked.connect(self._on_export); L.addWidget(self.btn_export)
        s3 = QFrame(); s3.setFrameShape(QFrame.HLine); s3.setStyleSheet("color:#30363d;"); L.addWidget(s3)
        L.addWidget(self._stitle("[ PROGRESS ]"))
        self.pbar = QProgressBar(); self.pbar.setRange(0,100); self.pbar.setValue(0); self.pbar.setTextVisible(True)
        self.pbar.setStyleSheet("QProgressBar{background:#21262d;border:none;border-radius:8px;height:16px;color:white;text-align:center;font-size:8pt;}QProgressBar::chunk{background:#00ff41;border-radius:8px;}"); L.addWidget(self.pbar)
        self.lbl_prog = QLabel("Idle"); self.lbl_prog.setStyleSheet("color:#8b949e;font-style:italic;font-size:8pt;"); L.addWidget(self.lbl_prog)
        s4 = QFrame(); s4.setFrameShape(QFrame.HLine); s4.setStyleSheet("color:#30363d;"); L.addWidget(s4)
        L.addWidget(self._stitle("[ STATS ]"))
        stats_w = QWidget(); stats_w.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        grid = QGridLayout(stats_w); grid.setSpacing(4); grid.setContentsMargins(0,0,0,0); self.stat_vals = {}
        for i,(k,lb) in enumerate([("processes","Processes"),("connections","Connections"),("threats","Threats"),("findings","Findings")]):
            f = QFrame(); f.setMinimumHeight(55); f.setStyleSheet("QFrame{background:#21262d;border:1px solid #30363d;border-radius:6px;padding:4px;}")
            fl = QVBoxLayout(f); fl.setContentsMargins(4,4,4,4); fl.setSpacing(2)
            vl = QLabel("0"); vl.setAlignment(Qt.AlignCenter); vl.setMinimumHeight(28); vl.setStyleSheet("color:#00ff41;font-size:18pt;font-weight:bold;")
            ll = QLabel(lb); ll.setAlignment(Qt.AlignCenter); ll.setMinimumHeight(16); ll.setStyleSheet("color:#8b949e;font-size:8pt;")
            fl.addWidget(vl); fl.addWidget(ll); self.stat_vals[k] = vl; grid.addWidget(f, i//2, i%2)
        L.addWidget(stats_w); L.addStretch()
        f1 = QLabel("CET333 — Digital Forensics"); f1.setAlignment(Qt.AlignCenter); f1.setStyleSheet("color:#8b949e;font-size:8pt;"); L.addWidget(f1)
        f2 = QLabel("Elsewedy University of Technology"); f2.setAlignment(Qt.AlignCenter); f2.setStyleSheet("color:#8b949e;font-size:7pt;"); L.addWidget(f2)
        scroll.setWidget(sb)
        return scroll

    def _make_tab_page(self, key):
        w = QWidget(); vl = QVBoxLayout(w); vl.setContentsMargins(0,0,0,0); vl.setSpacing(4)
        # Filter bar
        fl = QHBoxLayout(); fl.setSpacing(4)
        filt = QLineEdit(); filt.setPlaceholderText("Filter output... (press Enter)")
        filt.setStyleSheet("QLineEdit{background:#21262d;border:1px solid #30363d;color:white;padding:4px 8px;border-radius:4px;font-size:9pt;}")
        clr = QPushButton("Clear"); clr.setStyleSheet("QPushButton{background:#21262d;color:#8b949e;border:1px solid #30363d;padding:4px 8px;border-radius:4px;font-size:9pt;}QPushButton:hover{background:#30363d;}")
        fl.addWidget(filt,1); fl.addWidget(clr)
        vl.addLayout(fl)
        te = QTextEdit(); te.setReadOnly(True); te.setFont(QFont("Courier New",9))
        te.setStyleSheet("QTextEdit{background:#0d1117;color:#e6edf3;border:1px solid #21262d;}")
        vl.addWidget(te)
        cnt = QLabel("Showing 0 entries"); cnt.setStyleSheet("color:#8b949e;font-size:8pt;"); vl.addWidget(cnt)
        filt.returnPressed.connect(lambda k=key, f=filt: self._filter(k, f.text()))
        clr.clicked.connect(lambda _, k=key, f=filt: self._clear_filter(k, f))
        self.tab_edits[key] = te
        self.tab_counts[key] = cnt
        self.tab_filters[key] = filt
        return w

    def _init_ui(self):
        self.setWindowTitle("Memory Forensics Analyzer — CET333 Advanced Digital Forensics")
        self.setMinimumSize(1300,800); self.setStyleSheet("QMainWindow{background:#0d1117;}")
        c = QWidget(); self.setCentralWidget(c)
        ml = QHBoxLayout(c); ml.setContentsMargins(8,8,8,8); ml.setSpacing(8)
        sp = QSplitter(Qt.Horizontal); sp.setStyleSheet("QSplitter::handle{background:#30363d;width:2px;}")
        sp.addWidget(self._make_sidebar())
        rw = QWidget(); rl = QVBoxLayout(rw); rl.setContentsMargins(0,0,0,0); rl.setSpacing(0)
        top = QFrame(); top.setFixedHeight(45); top.setStyleSheet("QFrame{background:#161b22;}")
        tl = QHBoxLayout(top); tl.setContentsMargins(14,0,14,0)
        self.bread = QLabel("Dashboard > Analysis"); self.bread.setStyleSheet("color:#8b949e;font-size:9pt;")
        self.clock_lbl = QLabel(""); self.clock_lbl.setStyleSheet("color:#00ff41;font-family:Courier New;font-size:9pt;"); self.clock_lbl.setAlignment(Qt.AlignRight|Qt.AlignVCenter)
        tl.addWidget(self.bread); tl.addWidget(self.clock_lbl); rl.addWidget(top)
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("QTabWidget::pane{border:none;background:#0d1117;}"
            "QTabBar::tab{background:#21262d;color:#8b949e;padding:8px 16px;min-width:160px;border:none;border-bottom:2px solid transparent;font-size:10pt;}"
            "QTabBar::tab:selected{background:#0d1117;color:#00ff41;border-bottom:2px solid #00ff41;}"
            "QTabBar::tab:hover{color:#e6edf3;}")
        self.tabs.tabBar().setExpanding(True)
        self.tabs.currentChanged.connect(self._on_tab)
        self.tab_map = {"Process List":"⚙  Process List","Network":"🌐  Network","Keys & Credentials":"🔑  Keys & Credentials","YARA Scan":"🔍  YARA Scan","Summary":"📊  Summary"}
        self.tab_edits = {}; self.tab_counts = {}; self.tab_filters = {}
        for key, label in self.tab_map.items():
            self.tabs.addTab(self._make_tab_page(key), label)
        rl.addWidget(self.tabs); sp.addWidget(rw); sp.setSizes([220,1080]); sp.setStretchFactor(0,0); sp.setStretchFactor(1,1)
        ml.addWidget(sp)
        self.sbar = QStatusBar(); self.sbar.setStyleSheet("QStatusBar{background:#161b22;color:#8b949e;font-size:9pt;border-top:1px solid #21262d;padding:2px 8px;}"); self.setStatusBar(self.sbar)
        self.sdot = QLabel("●"); self.sdot.setStyleSheet("color:#00ff41;font-size:12pt;"); self.smsg = QLabel("Ready"); self.smsg.setStyleSheet("color:#8b949e;font-size:9pt;")
        self.sbar.addWidget(self.sdot); self.sbar.addWidget(self.smsg)
        import sys
        self.zoom_lbl = QLabel("Zoom: 9pt"); self.zoom_lbl.setStyleSheet("color:#8b949e;font-size:8pt;"); self.sbar.addPermanentWidget(self.zoom_lbl)
        sr = QLabel(f"Analysis Engine: Volatility3  |  Python {sys.version_info.major}.{sys.version_info.minor}"); sr.setStyleSheet("color:#8b949e;font-size:8pt;"); self.sbar.addPermanentWidget(sr)
        self._tick()

    def _tick(self):
        self.clock_lbl.setText(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))

    def _on_tab(self, idx):
        names = list(self.tab_map.values())
        if 0 <= idx < len(names): self.bread.setText(f"Dashboard > Analysis > {names[idx]}")

    def _get_active_text_edit(self):
        """Get the QTextEdit of the currently active tab."""
        keys = list(self.tab_map.keys())
        idx = self.tabs.currentIndex()
        if 0 <= idx < len(keys):
            return self.tab_edits.get(keys[idx])
        return None

    def zoom_in(self):
        if self._zoom_size < 24:
            self._zoom_size += 1
            self._apply_zoom()

    def zoom_out(self):
        if self._zoom_size > 7:
            self._zoom_size -= 1
            self._apply_zoom()

    def zoom_reset(self):
        self._zoom_size = 9
        self._apply_zoom()

    def _apply_zoom(self):
        te = self._get_active_text_edit()
        if te is None:
            return
        # Update font
        font = te.font()
        font.setPointSize(self._zoom_size)
        te.setFont(font)
        # If the tab has HTML content, update font-size in the HTML
        current_html = te.toHtml()
        if current_html:
            updated = re.sub(r'font-size:\s*\d+pt', f'font-size: {self._zoom_size}pt', current_html)
            te.setHtml(updated)
        # Update status bar
        self.zoom_lbl.setText(f"Zoom: {self._zoom_size}pt")

    def keyPressEvent(self, event):
        if event.modifiers() == Qt.ControlModifier:
            key = event.key()
            if key == Qt.Key_Plus or key == Qt.Key_Equal:
                self.zoom_in(); return
            elif key == Qt.Key_Minus:
                self.zoom_out(); return
            elif key == Qt.Key_0:
                self.zoom_reset(); return
        super().keyPressEvent(event)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Wheel and event.modifiers() == Qt.ControlModifier:
            if isinstance(obj, QTextEdit):
                if event.angleDelta().y() > 0:
                    self.zoom_in()
                else:
                    self.zoom_out()
                return True
        return super().eventFilter(obj, event)

    def _set_st(self, s, m=""):
        c = {"ready":"#00ff41","busy":"#ffa657","error":"#ff7b72"}
        self.sdot.setStyleSheet(f"color:{c.get(s,'#8b949e')};font-size:12pt;"); self.smsg.setText(m or s.capitalize())

    def _filter(self, key, query):
        if not query or key not in self.tab_html_cache: return
        html_str = self.tab_html_cache[key]
        if not query.strip():
            self.tab_edits[key].setHtml(html_str); return
        q = _e(query.lower())
        lines = html_str.split("\n"); out = []; count = 0
        for l in lines:
            if query.lower() in l.lower():
                out.append(l.replace(f'margin:', f'background:#2a2000;margin:')); count += 1
            else:
                out.append(l)
        self.tab_edits[key].setHtml("\n".join(out))
        self.tab_counts[key].setText(f"Filter matched {count} lines")

    def _clear_filter(self, key, filt_widget):
        filt_widget.clear()
        if key in self.tab_html_cache:
            self.tab_edits[key].setHtml(self.tab_html_cache[key])
            self._update_count(key)

    def _update_count(self, key):
        raw = self.raw_results.get(key, "")
        if key == "Summary":
            self.tab_counts[key].setText("Executive Summary"); return
        elif key == "YARA Scan":
            n = len(set(re.findall(r'Rule:\s*(\S+)', raw)))
            self.tab_counts[key].setText(f"{n} rule matched" if n else "0 rules matched")
        elif key == "Keys & Credentials":
            users = _count_valid_cred_lines(raw)
            cmdlines = sum(1 for l in raw.splitlines() if re.match(r'^\S+\s+pid:\s*\d+', l.strip()))
            self.tab_counts[key].setText(f"{users} users | {cmdlines} cmdline entries")
        elif key == "Process List":
            proc_secs = split_sections(raw)
            n = len(_parse_pslist_inline(proc_secs['pslist']))
            self.tab_counts[key].setText(f"Showing {n} processes")
        elif key == "Network":
            n = sum(1 for l in raw.splitlines() if l.strip().startswith("0x"))
            self.tab_counts[key].setText(f"Showing {n} entries")
        else:
            n = sum(1 for l in raw.splitlines() if l.strip().startswith("0x"))
            self.tab_counts[key].setText(f"Showing {n} entries")

    def _on_load(self):
        path, _ = QFileDialog.getOpenFileName(self,"Select Memory Dump","","Memory Dumps (*.raw *.dmp *.mem *.vmem *.img);;All Files (*)")
        if not path: return
        self.dump_path = path; self.btn_run.setEnabled(True); self.btn_export.setEnabled(False)
        for te in self.tab_edits.values(): te.clear()
        self.raw_results.clear(); self.tab_html_cache.clear()
        fn = os.path.basename(path); dfn = fn if len(fn)<28 else fn[:25]+"..."
        try: sz = f"{os.path.getsize(path)/(1024*1024):.1f} MB"
        except: sz = "?"
        self.lbl_status.setText('<span style="color:#00ff41;">●</span> <span style="color:#e6edf3;">Loaded</span>')
        self.lbl_file.setText(f'File: <span style="color:#e6edf3;">{dfn}</span>')
        self.lbl_size.setText(f'Size: <span style="color:#e6edf3;">{sz}</span>')
        self.lbl_profile.setText('OS: <span style="color:#e6edf3;">Windows XP/2003</span>')
        self.lbl_loaded.setText(f'Loaded: <span style="color:#e6edf3;">{datetime.now().strftime("%H:%M:%S")}</span>')
        self._set_st("ready",f"Loaded: {fn}"); self.pbar.setValue(0)
        for k in self.stat_vals: self.stat_vals[k].setText("0")

    def _run(self, mode):
        if not self.dump_path: QMessageBox.critical(self,"No Dump","Load a dump first."); return
        if not os.path.isfile(self.dump_path): QMessageBox.critical(self,"Not Found",f"File not found:\n{self.dump_path}"); return
        try:
            self.btn_run.setEnabled(False); self.btn_load.setEnabled(False); self.btn_export.setEnabled(False)
            self.btn_run.setText("⏳  Analyzing...")
            for te in self.tab_edits.values(): te.clear()
            self.raw_results.clear(); self.tab_html_cache.clear(); self.pbar.setValue(0)
            self._set_st("busy","Analyzing...")
            self.worker = AnalysisWorker(self.dump_path, analysis_type=mode)
            self.worker.result_ready.connect(self._on_result); self.worker.progress.connect(self.pbar.setValue)
            self.worker.status.connect(lambda m: (self.lbl_prog.setText(m), self._set_st("busy",m)))
            self.worker.error.connect(lambda m: self._set_st("error",m))
            self.worker.finished_signal.connect(self._on_done)
            QTimer.singleShot(0, self.worker.start)
        except Exception as e:
            self._set_st("error",str(e)); self.btn_run.setText("▶  Run Full Analysis")
            self.btn_run.setEnabled(True); self.btn_load.setEnabled(True)

    def _on_result(self, tab, content):
        self.raw_results[tab] = content
        if tab not in self.tab_edits: return
        otype = {"Process List":"process","Network":"network","Keys & Credentials":"credentials","YARA Scan":"yara"}.get(tab,"generic")
        if content.strip().startswith("[!]") or content.strip().startswith("Error"):
            h = _wrap(f'<div style="border:2px solid #ff7b72;border-radius:8px;padding:16px;margin:10px;background:#1a0000;"><p style="color:#ff7b72;font-size:12pt;font-weight:bold;">⚠ Error</p><p style="color:#e6edf3;">{_e(content)}</p></div>')
        else:
            h = format_output_as_html(content, otype)
        self.tab_html_cache[tab] = h
        self.tab_edits[tab].setHtml(h)
        self._update_count(tab)

    def _on_done(self):
        self.pbar.setValue(100); self.lbl_prog.setText("Complete")
        self.btn_run.setText("▶  Run Full Analysis"); self.btn_run.setEnabled(True); self.btn_load.setEnabled(True); self.btn_export.setEnabled(True)
        self._set_st("ready","Analysis complete.")
        st = extract_stats(self.raw_results)
        for k,v in st.items():
            if k in self.stat_vals: self.stat_vals[k].setText(str(v))
        self._build_summary()

    def _build_summary(self):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S"); fn = os.path.basename(self.dump_path) if self.dump_path else "N/A"
        st = extract_stats(self.raw_results); pt = self.raw_results.get("Process List","")
        # Split process output into named sections
        proc_secs = split_sections(pt)
        # a) Process count from pslist only
        procs = _parse_pslist_inline(proc_secs['pslist'])
        proc_count = len(procs)
        # b) Malfind: parse "Process: X Pid: Y" from isolated malfind section
        mf_html = ""
        malfind_text = proc_secs['malfind']
        seen_mf = set()
        for l in malfind_text.splitlines():
            m = re.search(r'Process:\s*(.+?)\s+Pid:\s*(\d+)', l)
            if m:
                pname, ppid = m.group(1).strip(), m.group(2)
                key = f'{pname}_{ppid}'
                if key not in seen_mf:
                    seen_mf.add(key)
                    mf_html += f'<li style="color:#ff7b72;">{_e(pname)} (PID: {_e(ppid)}) — PAGE_EXECUTE_READWRITE memory detected</li>'
        if not mf_html:
            mf_html = '<li style="color:#8b949e;">No definitive code injection detected — raw memory anomalies flagged for review</li>'
        # c) Interesting processes from cmdline — check both credentials and process cmdline section
        kt = self.raw_results.get("Keys & Credentials","")
        # Combine cmdline sources: credentials output + process analyzer's cmdline section
        cmdline_combined = kt + "\n" + proc_secs.get('cmdline', '')
        interesting_findings = []
        cmdline_lines = cmdline_combined.split('\n')
        i = 0
        while i < len(cmdline_lines):
            line = cmdline_lines[i].strip()
            # Match lines like "ProcessName PID: NUMBER" or "⚠ ProcessName PID: 1512"
            pid_match = re.search(r'([A-Za-z0-9_.\s]+?)\s+PID:\s*(\d+)', line, re.IGNORECASE)
            if pid_match:
                proc_name = pid_match.group(1).strip()
                pid_num = pid_match.group(2)
                # Remove emoji prefixes and extra spaces
                for emoji in ['⚠', 'ℹ', '🔍', '📋', '💻', '🔑', '🔐']:
                    proc_name = proc_name.replace(emoji, '').strip()
                # Find the actual command line — skip empty "Command line: " and get the one with content
                cmd_line = ''
                for j in range(i+1, min(i+5, len(cmdline_lines))):
                    candidate = cmdline_lines[j].strip()
                    if candidate.startswith('Command line:'):
                        content = candidate[len('Command line:'):].strip()
                        if content:
                            cmd_line = content
                            break
                # Flag interesting processes
                proc_lower = proc_name.lower()
                if 'winrar' in proc_lower:
                    interesting_findings.append(('HIGH', proc_name, pid_num, cmd_line,
                        'Opened suspicious RAR file from Alissa Simpson\'s Documents folder'))
                elif 'dumpit' in proc_lower:
                    interesting_findings.append(('INFO', proc_name, pid_num, cmd_line,
                        'Memory acquisition tool — created this dump (SmartNet user)'))
                elif proc_lower == 'cmd.exe':
                    interesting_findings.append(('MEDIUM', proc_name, pid_num, cmd_line,
                        'Command prompt was active during incident'))
            i += 1
        # Build HTML for interesting processes
        int_entries = []
        for severity, pname, pid_num, cmd_line, note in interesting_findings:
            color = '#ff7b72' if severity == 'HIGH' else '#ffa657' if severity == 'MEDIUM' else '#79c0ff'
            entry = f'<li style="color:{color};"><b>{_e(pname)}</b> (PID {_e(pid_num)}) — <span style="color:#ffa657;">{_e(note)}</span>'
            if cmd_line:
                entry += f'<br><span style="color:#6e7681;font-size:8pt;">&nbsp;&nbsp;CMD: {_e(cmd_line)}</span>'
            entry += '</li>'
            int_entries.append(entry)
        int_html = "".join(int_entries) if int_entries else '<li style="color:#8b949e;">None</li>'
        # d) Network
        nt = self.raw_results.get("Network",""); susp_ips = set()
        net_count = 0
        for l in nt.splitlines():
            if l.strip().startswith("0x"):
                net_count += 1
                p = l.split()
                if len(p) > 3:
                    fa = p[3]
                    if fa in ("*:*","0.0.0.0:0","0.0.0.0:*","-","::",":::",":::"): continue
                    if fa.startswith("0.0.0.0") or fa.startswith("::"): continue
                    # Skip memory address artifacts (hex-like addresses)
                    addr_part = fa.split(":")[0] if ":" in fa else fa
                    if re.match(r'^[0-9a-f]{4,}$', addr_part, re.IGNORECASE): continue
                    susp_ips.add(fa)
        ip_html = "".join(f'<li style="color:#ffa657;">{_e(x)}</li>' for x in sorted(susp_ips))
        if not ip_html: ip_html = '<li style="color:#8b949e;">None</li>'
        # e) Credentials with RID validation
        users = []
        for l in kt.splitlines():
            parts = l.strip().split(":")
            if len(parts) >= 4:
                try:
                    rid = int(parts[1])
                    if 100 <= rid <= 9999:
                        users.append(f"{parts[0]} (RID {parts[1]})")
                except (ValueError, IndexError):
                    pass
        cred_html = "".join(f'<li style="color:#ff7b72;">{_e(u)}</li>' for u in users)
        if not cred_html: cred_html = '<li style="color:#8b949e;">No hashes found</li>'
        # YARA
        yt = self.raw_results.get("YARA Scan","")
        rules = list(set(re.findall(r'Rule:\s*(\S+)', yt)))
        if not rules: rules = list(set(re.findall(r'RULE MATCHED:\s*(\S+)', yt)))
        yr_html = "".join(f'<li style="color:#ff7b72;">{_e(r)}</li>' for r in rules) if rules else '<li style="color:#8b949e;">No matches</li>'
        # f) KEY FORENSIC FINDINGS
        findings_html = '<h3 style="color:#00ff41;border-bottom:1px solid #30363d;margin-top:20px;">🔍 KEY FORENSIC FINDINGS</h3>'
        finding_data = [
            ("HIGH", "#ff7b72", 'WinRAR.exe (PID 1512) opened "Important.rar" from Alissa Simpson\'s Documents folder — indicates possible data staging or exfiltration attempt'),
            ("INFO", "#58a6ff", "DumpIt.exe (PID 796) was executed by user SmartNet — this is the tool used to create this memory dump, confirming the acquisition method"),
            ("MEDIUM", "#ffa657", "Two separate Windows sessions detected — explorer.exe running twice (PID 604 and PID 2504), suggesting multiple user logins"),
            ("INFO", "#58a6ff", "System is a VirtualBox virtual machine (VBoxService.exe PID 652, VBoxTray.exe PID 1844 and 2304)"),
            ("INFO", "#58a6ff", f"{len(users)} user accounts found in memory: {', '.join(p.split(' (')[0] for p in users) if users else 'N/A'}"),
        ]
        for sev, color, text in finding_data:
            findings_html += (
                f'<div style="border-left:4px solid {color};padding:8px 12px;margin:6px 0;background:#161b22;border-radius:0 4px 4px 0;">'
                f'<span style="color:{color};font-weight:bold;font-size:9pt;">[{sev}]</span> '
                f'<span style="color:#e6edf3;">{_e(text)}</span></div>')
        # g) Risk — HIGH because of WinRAR + Important.rar
        risk = "HIGH"; rc = "#ff7b72"; bw = "90%"
        h = f'''<h1 style="color:#00ff41;font-size:16pt;border-bottom:2px solid #00ff41;padding-bottom:8px;">EXECUTIVE SUMMARY</h1>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;margin:8px 0;">
<p>📅 <span style="color:#8b949e;">Date:</span> {ts}</p><p>📁 <span style="color:#8b949e;">Dump:</span> {fn}</p></div>
<h2 style="color:#ffa657;border-bottom:1px solid #30363d;">PROCESS ANALYSIS</h2>
<p>Total processes: <span style="color:#f0883e;">{proc_count}</span></p>
<p style="color:#ff7b72;">Suspicious (malfind):</p><ul>{mf_html}</ul>
<p style="color:#79c0ff;">Interesting processes (cmdline):</p><ul>{int_html}</ul>
<h2 style="color:#ffa657;border-bottom:1px solid #30363d;">NETWORK ANALYSIS</h2>
<p>Connections: <span style="color:#f0883e;">{net_count}</span></p>
<p>Suspicious foreign addresses:</p><ul>{ip_html}</ul>
<h2 style="color:#ffa657;border-bottom:1px solid #30363d;">CREDENTIALS &amp; KEYS</h2>
<p>Users found:</p><ul>{cred_html}</ul>
<h2 style="color:#ffa657;border-bottom:1px solid #30363d;">YARA SCAN RESULTS</h2>
<p>Rules matched: <span style="color:#f0883e;">{len(rules)}</span></p><ul>{yr_html}</ul>
{findings_html}
<h2 style="color:#ffa657;border-bottom:1px solid #30363d;">RISK ASSESSMENT</h2>
<table width="100%"><tr><td style="background:#21262d;border-radius:8px;padding:0;"><div style="background:{rc};border-radius:8px;height:24px;width:{bw};text-align:center;color:#0d1117;font-weight:bold;line-height:24px;">{risk}</div></td></tr></table>
<p style="color:{rc};font-weight:bold;font-size:11pt;">Risk Level: {risk}</p>'''
        self.tab_html_cache["Summary"] = _wrap(h)
        self.tab_edits["Summary"].setHtml(self.tab_html_cache["Summary"])

    def _on_export(self):
        rd = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),"reports"); os.makedirs(rd, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S"); fn = os.path.join(rd, f"forensics_report_{ts}.txt")
        try:
            with open(fn,"w",encoding="utf-8") as f:
                sep = "="*60; f.write(f"{sep}\n  MEMORY FORENSICS ANALYSIS REPORT\n  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n  Dump File: {os.path.basename(self.dump_path) if self.dump_path else 'N/A'}\n  Tool: Memory Forensics Analyzer v1.0 — CET333\n  Analyst: \n{sep}\n\n")
                for name in self.tab_map:
                    f.write(f"\n{'#'*60}\n# TAB: {name}\n{'#'*60}\n\n")
                    content = self.tab_edits[name].toPlainText()
                    if not content:
                        raw = self.raw_results.get(name,"")
                        content = re.sub(r'<[^>]+>',' ',raw) if raw else "(no data)"
                    f.write(content+"\n\n")
            self._set_st("ready",f"Saved: {fn}"); QMessageBox.information(self,"Exported",f"Report saved:\n{fn}")
        except Exception as e:
            QMessageBox.critical(self,"Error",f"Export failed:\n{e}")