"""
YARA Scanner Module
====================
Compiles and runs YARA rules against memory dump files.
Gracefully handles the case where yara-python is not installed.
"""

import os
from datetime import datetime


class YaraScanner:
    """Scans a memory dump file using compiled YARA rules."""

    def __init__(self, dump_path, rules_path):
        """
        Initialize the YaraScanner.

        Args:
            dump_path (str): Absolute path to the memory dump file.
            rules_path (str): Absolute path to the .yar rules file.
        """
        self.dump_path = dump_path
        self.dump_name = os.path.basename(dump_path)
        self.rules_path = rules_path
        self.compiled_rules = None
        self.matches = []
        self.error_message = None
        self._yara_available = True

        # Attempt import once at init time
        try:
            import yara  # noqa: F401
        except ImportError:
            self._yara_available = False
            self.error_message = (
                "[!] yara-python is not installed.\n"
                "    Install it with:  pip install yara-python\n"
                "    YARA scanning is disabled until the package is available."
            )

    def _build_header(self, title):
        """Build a formatted section header."""
        sep = "=" * 60
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return (
            f"\n{sep}\n"
            f"  {title}\n"
            f"  Dump: {self.dump_name}\n"
            f"  Time: {timestamp}\n"
            f"{sep}\n\n"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compile_rules(self):
        """
        Compile the YARA rules file.

        Returns:
            bool: True if compilation succeeded, False otherwise.
        """
        if not self._yara_available:
            return False

        import yara

        try:
            if not os.path.isfile(self.rules_path):
                self.error_message = (
                    f"[!] YARA rules file not found: {self.rules_path}"
                )
                return False

            self.compiled_rules = yara.compile(filepath=self.rules_path)
            return True

        except yara.SyntaxError as e:
            self.error_message = (
                f"[!] YARA syntax error in '{self.rules_path}':\n    {e}"
            )
            return False
        except Exception as e:
            self.error_message = (
                f"[!] Unexpected error compiling YARA rules:\n    {e}"
            )
            return False

    def scan_dump(self):
        """
        Scan the memory dump file with the compiled YARA rules.

        Returns:
            list: A list of match description strings, or an empty list.
        """
        if not self._yara_available:
            return []

        if self.compiled_rules is None:
            compiled_ok = self.compile_rules()
            if not compiled_ok:
                return []

        try:
            raw_matches = self.compiled_rules.match(filepath=self.dump_path)
            self.matches = []
            for match in raw_matches:
                rule_name = match.rule
                meta = match.meta
                description = meta.get("description", "No description")
                matched_strings = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        offset = instance.offset
                        identifier = string_match.identifier
                        matched_strings.append(
                            f"      Offset 0x{offset:08X} | {identifier}"
                        )
                entry = (
                    f"  Rule: {rule_name}\n"
                    f"    Description: {description}\n"
                    f"    Matched strings:\n"
                    + "\n".join(matched_strings[:50])  # Cap display
                )
                self.matches.append(entry)
            return self.matches

        except Exception as e:
            self.error_message = (
                f"[!] Error during YARA scan:\n    {e}"
            )
            return []

    def get_results_string(self):
        """
        Return a formatted, human-readable results string.

        Returns:
            str: Complete results including header, matches, and summary.
        """
        header = self._build_header("YARA SCAN RESULTS")

        # If YARA is not available or an error occurred
        if self.error_message and not self.matches:
            return header + self.error_message + "\n"

        # Run the scan if not already done
        if not self.matches:
            self.scan_dump()

        # Still no matches after scanning?
        if not self.matches:
            if self.error_message:
                return header + self.error_message + "\n"
            return header + "[i] No YARA rule matches found in the dump.\n"

        body = "\n\n".join(self.matches)
        footer = (
            f"\n{'─' * 60}\n"
            f"  Total YARA matches: {len(self.matches)}\n"
            f"{'─' * 60}\n"
        )
        return header + body + footer
