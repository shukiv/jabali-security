"""Heuristic pattern scanner for detecting malicious code in files."""

from __future__ import annotations

import re

from lib.models import Finding

_MAX_MATCHES_PER_PATTERN = 10

# (rule_name, raw_pattern_bytes, score, description, re_flags)
_RAW_PATTERNS: list[tuple[str, bytes, int, str, int]] = [
    # ── PHP Obfuscation (high scores) ──
    (
        "eval_base64",
        rb"eval\s*\(\s*base64_decode\s*\(",
        40,
        "eval(base64_decode()) - encoded execution",
        re.IGNORECASE,
    ),
    (
        "gzinflate_chain",
        rb"(?:gzinflate|gzuncompress|str_rot13|base64_decode)\s*\(.{0,2000}(?:gzinflate|gzuncompress|str_rot13|base64_decode)",
        45,
        "Obfuscation chain",
        re.IGNORECASE | re.DOTALL,
    ),
    (
        "preg_replace_e",
        rb"preg_replace\s*\(\s*[\"']/[^/]+/e",
        35,
        "preg_replace with /e modifier",
        re.IGNORECASE,
    ),
    (
        "assert_string",
        rb"assert\s*\(\s*\$",
        30,
        "assert() with variable input",
        re.IGNORECASE,
    ),
    # ── PHP Execution functions (medium-high) ──
    (
        "shell_exec",
        rb"\b(?:shell_exec|system|passthru|popen|proc_open)\s*\(",
        30,
        "Shell execution function",
        re.IGNORECASE,
    ),
    (
        "exec_func",
        rb"\bexec\s*\(",
        25,
        "exec() function call",
        re.IGNORECASE,
    ),
    (
        "backtick_exec",
        rb"`\$[^`]+`",
        30,
        "Backtick execution with variable",
        0,
    ),
    # ── PHP Dynamic/Dangerous patterns ──
    (
        "dynamic_func_call",
        rb"\$\w+\s*\(\s*\$",
        25,
        "Dynamic function call via variable",
        0,
    ),
    (
        "dynamic_include",
        rb"(?:include|require)(?:_once)?\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)",
        40,
        "Dynamic include with user input",
        re.IGNORECASE,
    ),
    (
        "create_function",
        rb"create_function\s*\(",
        35,
        "create_function() - deprecated code execution",
        re.IGNORECASE,
    ),
    (
        "call_user_func",
        rb"call_user_func(?:_array)?\s*\(\s*\$",
        25,
        "call_user_func with variable",
        re.IGNORECASE,
    ),
    # ── PHP File/Network operations ──
    (
        "file_put_contents",
        rb"file_put_contents\s*\(\s*\$",
        20,
        "file_put_contents with variable path",
        re.IGNORECASE,
    ),
    (
        "fwrite_fopen",
        rb"fwrite\s*\(\s*fopen\s*\(",
        20,
        "Direct file write via fopen",
        re.IGNORECASE,
    ),
    (
        "curl_exec_post",
        rb"curl_setopt.{0,500}CURLOPT_POSTFIELDS",
        15,
        "cURL POST data exfiltration",
        re.IGNORECASE | re.DOTALL,
    ),
    (
        "fsockopen",
        rb"fsockopen\s*\(",
        20,
        "Raw socket connection",
        re.IGNORECASE,
    ),
    (
        "mail_injection",
        rb"@?mail\s*\(\s*\$",
        15,
        "mail() with variable recipient",
        re.IGNORECASE,
    ),
    # ── Obfuscation indicators ──
    (
        "hex_escape",
        rb"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}",
        25,
        "Excessive hex escaping",
        0,
    ),
    (
        "chr_concat",
        rb"chr\s*\(\s*\d+\s*\)\s*\..{0,200}chr\s*\(\s*\d+\s*\)\s*\..{0,200}chr\s*\(\s*\d+\s*\)",
        30,
        "chr() concatenation chain",
        re.IGNORECASE | re.DOTALL,
    ),
    (
        "long_base64",
        rb"[A-Za-z0-9+/=]{500,}",
        20,
        "Long base64-encoded string (>500 chars)",
        0,
    ),
    (
        "variable_vars",
        rb"\$\{\s*\$",
        20,
        "Variable variables ($$var)",
        0,
    ),
    (
        "ini_set_disable",
        rb"ini_set\s*\(\s*[\"'](?:disable_functions|open_basedir)",
        35,
        "Attempting to override security settings",
        re.IGNORECASE,
    ),
    # ── JavaScript threats ──
    (
        "js_eval_atob",
        rb"eval\s*\(\s*atob\s*\(",
        35,
        "eval(atob()) - JS encoded execution",
        re.IGNORECASE,
    ),
    (
        "js_fromcharcode",
        rb"String\.fromCharCode\s*\(\d+\s*,.{0,500}\d+\s*,.{0,500}\d+\s*,",
        25,
        "String.fromCharCode chain",
        re.IGNORECASE | re.DOTALL,
    ),
    (
        "js_document_write",
        rb"document\.write\s*\(\s*unescape\s*\(",
        30,
        "document.write(unescape()) obfuscation",
        re.IGNORECASE,
    ),
    # ── Shell threats ──
    (
        "wget_curl_pipe",
        rb"(?:wget|curl)\s+.{0,500}\|\s*(?:bash|sh|python|perl)",
        40,
        "Download and pipe to interpreter",
        re.IGNORECASE | re.DOTALL,
    ),
    (
        "reverse_shell",
        rb"(?:bash\s+-i\s+>&|/dev/tcp/|nc\s+.*-e\s+/bin)",
        50,
        "Reverse shell pattern",
        re.IGNORECASE,
    ),
    (
        "chmod_exec",
        rb"chmod\s+(?:\+x|[0-7]*[1357][0-7]*)",
        20,
        "Making file executable",
        0,
    ),
    # ── Webshell indicators ──
    (
        "webshell_auth",
        rb"\$(?:pass|password|auth)\s*==?\s*[\"'][^\"']{4,}[\"']",
        15,
        "Hardcoded password check (webshell auth)",
        0,
    ),
    (
        "webshell_upload",
        rb"move_uploaded_file\s*\(\s*\$_FILES",
        10,
        "File upload handler (context-dependent)",
        re.IGNORECASE,
    ),
    (
        "php_uname",
        rb"php_uname\s*\(\s*\)",
        15,
        "System information disclosure",
        re.IGNORECASE,
    ),
    (
        "disable_errors",
        rb"(?:error_reporting\s*\(\s*0|ini_set\s*\(\s*[\"']display_errors[\"'])",
        10,
        "Error suppression",
        re.IGNORECASE,
    ),
]


class HeuristicScanner:
    name = "heuristic"

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled
        self._patterns: list[tuple[str, re.Pattern[bytes], int, str]] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        for rule_name, raw, score, desc, flags in _RAW_PATTERNS:
            self._patterns.append((rule_name, re.compile(raw, flags), score, desc))

    async def scan(self, path: str, content: bytes) -> list[Finding]:
        if not content:
            return []

        # Skip binary files: check first 512 bytes for null bytes
        header = content[:512]
        if b"\x00" in header:
            return []

        findings: list[Finding] = []
        for rule_name, pattern, score, desc in self._patterns:
            match_count = 0
            for match in pattern.finditer(content):
                match_count += 1
                if match_count > _MAX_MATCHES_PER_PATTERN:
                    break
                raw_match = match.group(0)[:100]
                findings.append(Finding(
                    scanner="heuristic",
                    rule=rule_name,
                    score=score,
                    description=desc,
                    metadata={
                        "offset": match.start(),
                        "match": raw_match.decode("utf-8", errors="replace"),
                    },
                ))
        return findings

    @property
    def enabled(self) -> bool:
        return self._enabled
