import subprocess
import os
from datetime import datetime

class ProcessAnalyzer:
    VOL_PATH = r"D:\volatility3-develop\volatility_2.6_win64_standalone\volatility_2.6_win64_standalone.exe"

    def __init__(self, dump_path):
        self.dump_path = dump_path
        self.dump_name = os.path.basename(dump_path)

    def _run_volatility(self, plugin, extra_args=None):
        cmd = [self.VOL_PATH, "-f", self.dump_path, "--profile=Win7SP1x64", plugin]
        if extra_args:
            cmd.extend(extra_args)
        try:
            result = subprocess.run(cmd, timeout=1200, capture_output=True, text=True, encoding="utf-8", errors="replace")
            return result.stdout
        except Exception as e:
            return f"[!] ERROR: {e}"

    def _build_header(self, title):
        sep = "=" * 60
        return f"\n{sep}\n  {title}\n  Dump: {self.dump_name}\n  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{sep}\n\n"

    def get_process_list(self):
        return self._build_header("PROCESS LIST (pslist)") + self._run_volatility("pslist")

    def get_process_tree(self):
        return self._build_header("PROCESS TREE (pstree)") + self._run_volatility("pstree")

    def detect_code_injection(self):
        return self._build_header("CODE INJECTION DETECTION (malfind)") + self._run_volatility("malfind")

    def get_dlls(self, pid=None):
        extra = ["-p", str(pid)] if pid else []
        return self._build_header(f"DLL LIST (dlllist)" + (f" - PID {pid}" if pid else "")) + self._run_volatility("dlllist", extra_args=extra)