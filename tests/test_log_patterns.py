"""Tests for regex patterns in log_parser.py and audit_log_parser.py."""

from __future__ import annotations

from lib.bruteforce.log_parser import _LOG_PATTERNS
from lib.waf.audit_log_parser import (
    _REQUEST_LINE_RE,
    _RULE_ID_RE,
    _RULE_MSG_RE,
    _SECTION_A_RE,
    _SECTION_RE,
    _SEVERITY_RE,
    ModSecAuditLogParser,
)


def _match_ip(service: str, rule_index: int, line: str) -> str | None:
    """Run a specific pattern against a log line and return the captured IP."""
    patterns = _LOG_PATTERNS[service]
    _, pattern = patterns[rule_index]
    m = pattern.search(line)
    if m:
        return m.group("ip")
    return None


class TestSSHPatterns:
    def test_failed_password(self) -> None:
        line = "Mar 26 10:15:30 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2"
        ip = _match_ip("ssh", 0, line)
        assert ip == "192.168.1.100"

    def test_failed_password_invalid_user(self) -> None:
        line = "Mar 26 10:15:30 server sshd[1234]: Failed password for invalid user test from 10.0.0.50 port 22 ssh2"
        ip = _match_ip("ssh", 0, line)
        assert ip == "10.0.0.50"

    def test_invalid_user(self) -> None:
        line = "Mar 26 10:15:30 server sshd[1234]: Invalid user hacker from 10.0.0.1 port 22"
        ip = _match_ip("ssh", 1, line)
        assert ip == "10.0.0.1"

    def test_connection_closed_preauth(self) -> None:
        line = "Mar 26 10:15:30 server sshd[1234]: Connection closed by authenticating user root 172.16.0.5 port 22 [preauth]"
        ip = _match_ip("ssh", 2, line)
        assert ip == "172.16.0.5"


class TestDovecotPatterns:
    def test_auth_failed(self) -> None:
        line = "Mar 26 10:15:30 server auth-worker(1234): password(user@domain) authentication failed rip=10.0.0.5"
        ip = _match_ip("dovecot", 0, line)
        assert ip == "10.0.0.5"

    def test_auth_failed_alternate(self) -> None:
        line = "Mar 26 10:15:30 mail auth-worker(5678): auth failed rip=203.0.113.10"
        ip = _match_ip("dovecot", 0, line)
        assert ip == "203.0.113.10"


class TestPostfixPatterns:
    def test_sasl_login_failed(self) -> None:
        line = "Mar 26 10:15:30 server postfix/smtpd[1234]: SASL LOGIN authentication failed [203.0.113.5]"
        ip = _match_ip("postfix", 0, line)
        assert ip == "203.0.113.5"

    def test_sasl_plain_failed(self) -> None:
        line = "Mar 26 10:15:30 server postfix/smtpd[9999]: SASL PLAIN authentication failed [10.10.10.1]"
        ip = _match_ip("postfix", 0, line)
        assert ip == "10.10.10.1"


class TestStalwartPatterns:
    def test_auth_failed(self) -> None:
        line = "2026-03-26T10:15:30Z WARN Authentication failed (auth.failed) remote-ip = 44.55.66.77, protocol = imap"
        ip = _match_ip("stalwart", 0, line)
        assert ip == "44.55.66.77"

    def test_security_auth_failed(self) -> None:
        line = "2026-03-26T10:15:30Z WARN (security.authentication-failed) remote-ip = 99.88.77.66, protocol = smtp"
        ip = _match_ip("stalwart", 1, line)
        assert ip == "99.88.77.66"

    def test_brute_force(self) -> None:
        line = "2026-03-26T10:15:30Z WARN (security.brute-force) too many auth attempts remote-ip = 11.22.33.44"
        ip = _match_ip("stalwart", 2, line)
        assert ip == "11.22.33.44"


class TestNoFalseMatch:
    def test_normal_log_line_no_match(self) -> None:
        line = "Mar 26 10:15:30 server sshd[1234]: Accepted password for admin from 192.168.1.100 port 22 ssh2"
        for _name, patterns in _LOG_PATTERNS.items():
            for _rule_name, pattern in patterns:
                assert pattern.search(line) is None


class TestModSecSectionA:
    def test_parse_client_ip(self) -> None:
        section_a = "[26/Mar/2026:10:15:30 +0000] YWJjZGVm 192.168.1.50 12345 10.0.0.1"
        m = _SECTION_A_RE.search(section_a)
        assert m is not None
        assert m.group("src_ip") == "192.168.1.50"
        assert m.group("dst_ip") == "10.0.0.1"


class TestModSecSectionB:
    def test_parse_request_method_and_uri(self) -> None:
        line = "POST /wp-login.php HTTP/1.1"
        m = _REQUEST_LINE_RE.match(line)
        assert m is not None
        assert m.group("method") == "POST"
        assert m.group("uri") == "/wp-login.php"

    def test_get_request(self) -> None:
        line = "GET /index.html HTTP/1.1"
        m = _REQUEST_LINE_RE.match(line)
        assert m is not None
        assert m.group("method") == "GET"
        assert m.group("uri") == "/index.html"


class TestModSecSectionH:
    def test_parse_rule_id(self) -> None:
        line = 'Message: [id "941100"] [msg "XSS Attack"] [severity "CRITICAL"]'
        id_m = _RULE_ID_RE.search(line)
        assert id_m is not None
        assert id_m.group(1) == "941100"

    def test_parse_rule_msg(self) -> None:
        line = 'Message: [id "941100"] [msg "XSS Attack Detected"] [severity "CRITICAL"]'
        msg_m = _RULE_MSG_RE.search(line)
        assert msg_m is not None
        assert msg_m.group(1) == "XSS Attack Detected"

    def test_parse_severity(self) -> None:
        line = 'Message: [id "941100"] [msg "XSS Attack"] [severity "CRITICAL"]'
        sev_m = _SEVERITY_RE.search(line)
        assert sev_m is not None
        assert sev_m.group(1) == "CRITICAL"

    def test_all_fields_from_single_line(self) -> None:
        line = 'Message: [id "942100"] [msg "SQL Injection"] [severity "WARNING"]'
        assert _RULE_ID_RE.search(line).group(1) == "942100"
        assert _RULE_MSG_RE.search(line).group(1) == "SQL Injection"
        assert _SEVERITY_RE.search(line).group(1) == "WARNING"


class TestModSecSectionBoundary:
    def test_section_marker_v2(self) -> None:
        line = "--abc123-A--"
        m = _SECTION_RE.match(line)
        assert m is not None
        assert m.group(1) == "A"

    def test_section_marker_v3(self) -> None:
        line = "---abc123---A---"
        m = _SECTION_RE.match(line)
        assert m is not None
        assert m.group(1) == "A"

    def test_section_z_marks_end(self) -> None:
        line = "--abc123-Z--"
        m = _SECTION_RE.match(line)
        assert m is not None
        assert m.group(1) == "Z"


class TestParseEntryIntegration:
    def test_full_entry_parsed(self) -> None:
        parser = ModSecAuditLogParser("/dev/null")
        lines = [
            "--abc123-A--",
            "[26/Mar/2026:10:15:30 +0000] abc123 192.168.1.50 12345 10.0.0.1",
            "--abc123-B--",
            "POST /wp-login.php HTTP/1.1",
            "Host: example.com",
            "--abc123-H--",
            'Message: [id "941100"] [msg "XSS Attack Detected"] [severity "CRITICAL"]',
            "Action: deny",
            "--abc123-Z--",
        ]
        event = parser._parse_entry(lines)
        assert event is not None
        assert event.client_ip == "192.168.1.50"
        assert event.method == "POST"
        assert event.uri == "/wp-login.php"
        assert event.rule_id == 941100
        assert event.rule_msg == "XSS Attack Detected"
        assert event.severity == "CRITICAL"
        assert event.action == "deny"
        assert event.hostname == "example.com"

    def test_entry_without_section_h_returns_none(self) -> None:
        parser = ModSecAuditLogParser("/dev/null")
        lines = [
            "--abc123-A--",
            "[26/Mar/2026:10:15:30 +0000] abc123 192.168.1.50 12345 10.0.0.1",
            "--abc123-B--",
            "GET / HTTP/1.1",
            "--abc123-Z--",
        ]
        event = parser._parse_entry(lines)
        assert event is None

    def test_empty_entry_returns_none(self) -> None:
        parser = ModSecAuditLogParser("/dev/null")
        event = parser._parse_entry([])
        assert event is None
