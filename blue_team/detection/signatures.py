"""
Signature Detection - Pattern-based threat detection
======================================================
Matches network traffic & events against known attack signatures.
"""

import logging
import re
from typing import Optional

from blue_team.models import Alert, DetectionRule

logger = logging.getLogger("blue_team.detection")

# Default built-in signatures
DEFAULT_SIGNATURES = [
    {
        "name": "SQL Injection Attempt",
        "pattern": r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table|;\s*delete\s+from)",
        "severity": "high",
        "description": "Detected SQL injection pattern in request",
    },
    {
        "name": "XSS Attack",
        "pattern": r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|<svg\s+onload|<img\s+.*onerror)",
        "severity": "medium",
        "description": "Detected cross-site scripting pattern",
    },
    {
        "name": "Command Injection",
        "pattern": r"(?:;\s*(?:ls|cat|whoami|id|uname|pwd)|\|\s*(?:cat|grep|awk)|`[^`]+`|\$\(.*\))",
        "severity": "critical",
        "description": "Detected OS command injection attempt",
    },
    {
        "name": "Path Traversal",
        "pattern": r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f){2,}",
        "severity": "high",
        "description": "Detected directory traversal attempt",
    },
    {
        "name": "Port Scan Detection",
        "pattern": r"__PORT_SCAN__",  # Special: detected by traffic analysis, not regex
        "severity": "medium",
        "description": "Detected port scanning activity",
    },
    {
        "name": "Brute Force Login",
        "pattern": r"__BRUTE_FORCE__",  # Special: detected by rate analysis
        "severity": "high",
        "description": "Detected brute force authentication attempt",
    },
    {
        "name": "Nmap Scan",
        "pattern": r"(?i)(nmap|masscan|zmap)",
        "severity": "medium",
        "description": "Detected network scanning tool signature",
    },
    {
        "name": "Metasploit Payload",
        "pattern": r"(?i)(meterpreter|reverse_tcp|bind_tcp|shell_reverse|msf|metasploit)",
        "severity": "critical",
        "description": "Detected Metasploit framework signature",
    },
    {
        "name": "XML External Entity",
        "pattern": r"(?i)(<!ENTITY|<!DOCTYPE.*SYSTEM|ENTITY\s+xxe)",
        "severity": "high",
        "description": "Detected XXE injection attempt",
    },
    {
        "name": "LDAP Injection",
        "pattern": r"(?:\*\)\(|\)\(\||\(\&|\)\)\(|\(\|)",
        "severity": "high",
        "description": "Detected LDAP injection attempt",
    },
]


class SignatureDetector:
    """
    Pattern-based detection engine.
    Matches traffic/events against known attack signatures.
    """

    def __init__(self):
        self._compiled_rules = {}
        self._load_rules()

    def _load_rules(self):
        """Load detection rules from database and defaults."""
        # Load from database
        db_rules = DetectionRule.objects.filter(enabled=True, rule_type=DetectionRule.RuleType.SIGNATURE)
        for rule in db_rules:
            try:
                self._compiled_rules[rule.name] = {
                    "pattern": re.compile(rule.rule_content),
                    "rule": rule,
                }
            except re.error as e:
                logger.warning(f"Invalid regex in rule '{rule.name}': {e}")

        # Add defaults that aren't already in DB
        existing_names = set(self._compiled_rules.keys())
        for sig in DEFAULT_SIGNATURES:
            if sig["name"] not in existing_names and not sig["pattern"].startswith("__"):
                try:
                    self._compiled_rules[sig["name"]] = {
                        "pattern": re.compile(sig["pattern"]),
                        "severity": sig["severity"],
                        "description": sig["description"],
                    }
                except re.error:
                    pass

        logger.info(f"Loaded {len(self._compiled_rules)} signature rules")

    def check(self, content: str, context: dict = None) -> list:
        """
        Check content against all signatures.

        Args:
            content: String to check (payload, URL, log entry, etc.)
            context: Additional context (source_ip, dest_port, etc.)

        Returns:
            List of matched signature dicts.
        """
        context = context or {}
        matches = []

        for name, rule_data in self._compiled_rules.items():
            pattern = rule_data["pattern"]
            try:
                match = pattern.search(content)
                if match:
                    # Get severity from DB rule or default
                    if "rule" in rule_data:
                        severity = "high"  # Default for DB rules
                    else:
                        severity = rule_data.get("severity", "medium")

                    matches.append({
                        "rule_name": name,
                        "severity": severity,
                        "description": rule_data.get("description", ""),
                        "matched_text": match.group()[:100],
                        "position": match.start(),
                    })

                    # Update hit count if it's a DB rule
                    if "rule" in rule_data:
                        rule_obj = rule_data["rule"]
                        rule_obj.hit_count += 1
                        rule_obj.save(update_fields=["hit_count"])

            except Exception as e:
                logger.error(f"Error checking rule '{name}': {e}")

        return matches

    def check_traffic(self, traffic_entry: dict) -> list:
        """Check a traffic log entry against signatures."""
        # Combine all checkable fields
        content_parts = [
            traffic_entry.get("payload_preview", ""),
            traffic_entry.get("url", ""),
            traffic_entry.get("headers", ""),
            traffic_entry.get("user_agent", ""),
        ]
        content = " ".join(str(p) for p in content_parts if p)
        return self.check(content, context=traffic_entry)

    def detect_port_scan(self, source_ip: str, recent_ports: list, time_window_seconds: int = 60) -> Optional[dict]:
        """
        Detect port scanning behavior based on connection patterns.

        Args:
            source_ip: Source IP to check.
            recent_ports: List of ports connected to in the time window.
            time_window_seconds: Time window to consider.

        Returns:
            Alert info dict if port scan detected, None otherwise.
        """
        unique_ports = len(set(recent_ports))

        if unique_ports > 10:
            return {
                "rule_name": "Port Scan Detection",
                "severity": "medium" if unique_ports < 50 else "high",
                "description": f"Port scan detected from {source_ip}: {unique_ports} unique ports in {time_window_seconds}s",
                "source_ip": source_ip,
                "ports_scanned": unique_ports,
            }
        return None

    def detect_brute_force(self, source_ip: str, failed_attempts: int, time_window_seconds: int = 300) -> Optional[dict]:
        """
        Detect brute force login attempts.

        Args:
            source_ip: Source IP to check.
            failed_attempts: Number of failed authentication attempts.
            time_window_seconds: Time window to consider.

        Returns:
            Alert info dict if brute force detected, None otherwise.
        """
        if failed_attempts > 5:
            return {
                "rule_name": "Brute Force Login",
                "severity": "high" if failed_attempts > 20 else "medium",
                "description": f"Brute force detected from {source_ip}: {failed_attempts} failed attempts in {time_window_seconds}s",
                "source_ip": source_ip,
                "failed_attempts": failed_attempts,
            }
        return None

    def add_rule(self, name: str, pattern: str, description: str = "") -> bool:
        """Add a new detection rule dynamically."""
        try:
            compiled = re.compile(pattern)
            rule, created = DetectionRule.objects.get_or_create(
                name=name,
                defaults={
                    "rule_type": DetectionRule.RuleType.SIGNATURE,
                    "rule_content": pattern,
                    "description": description,
                    "auto_generated": True,
                },
            )
            self._compiled_rules[name] = {"pattern": compiled, "rule": rule}
            logger.info(f"{'Created' if created else 'Updated'} detection rule: {name}")
            return True
        except re.error as e:
            logger.error(f"Invalid regex for rule '{name}': {e}")
            return False

    def reload_rules(self):
        """Reload all rules from the database."""
        self._compiled_rules.clear()
        self._load_rules()
