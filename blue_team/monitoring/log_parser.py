"""
Log Parser and Network Traffic Monitor
=========================================
Ingests and normalizes logs from multiple sources.
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional

from blue_team.models import TrafficLog

logger = logging.getLogger("blue_team.monitoring")


class LogParser:
    """
    Unified log parser that ingests and normalizes events
    from multiple sources (syslog, application logs, IDS alerts).
    """

    # Common log format patterns
    SYSLOG_PATTERN = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*"
        r"(?P<message>.+)$"
    )

    APACHE_PATTERN = re.compile(
        r"^(?P<source_ip>\S+)\s+\S+\s+\S+\s+"
        r"\[(?P<timestamp>[^\]]+)\]\s+"
        r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+'
        r"(?P<status>\d+)\s+(?P<size>\d+)"
    )

    AUTH_FAILURE_PATTERN = re.compile(
        r"(?i)(?:failed\s+(?:password|login)|authentication\s+failure|invalid\s+(?:user|password)|access\s+denied)"
    )

    def parse_syslog(self, line: str) -> Optional[dict]:
        """Parse a syslog-format log line."""
        match = self.SYSLOG_PATTERN.match(line)
        if match:
            return {
                "source": "syslog",
                "timestamp": match.group("timestamp"),
                "hostname": match.group("hostname"),
                "program": match.group("program"),
                "pid": match.group("pid"),
                "message": match.group("message"),
                "raw": line,
            }
        return None

    def parse_apache_log(self, line: str) -> Optional[dict]:
        """Parse an Apache/Nginx access log line."""
        match = self.APACHE_PATTERN.match(line)
        if match:
            return {
                "source": "webserver",
                "source_ip": match.group("source_ip"),
                "timestamp": match.group("timestamp"),
                "method": match.group("method"),
                "url": match.group("url"),
                "status": int(match.group("status")),
                "size": int(match.group("size")),
                "raw": line,
            }
        return None

    def parse_json_log(self, line: str) -> Optional[dict]:
        """Parse a JSON-formatted log entry."""
        try:
            data = json.loads(line)
            data["source"] = data.get("source", "json_log")
            return data
        except json.JSONDecodeError:
            return None

    def parse_auto(self, line: str) -> Optional[dict]:
        """Auto-detect log format and parse."""
        line = line.strip()
        if not line:
            return None

        # Try JSON first
        if line.startswith("{"):
            result = self.parse_json_log(line)
            if result:
                return result

        # Try Apache format
        result = self.parse_apache_log(line)
        if result:
            return result

        # Try syslog
        result = self.parse_syslog(line)
        if result:
            return result

        # Fallback: raw line
        return {"source": "unknown", "message": line, "raw": line}

    def detect_auth_failure(self, log_entry: dict) -> bool:
        """Check if a log entry indicates an authentication failure."""
        message = log_entry.get("message", "") + " " + log_entry.get("raw", "")
        return bool(self.AUTH_FAILURE_PATTERN.search(message))

    def parse_file(self, filepath: str, max_lines: int = 10000) -> list:
        """Parse an entire log file."""
        entries = []
        try:
            with open(filepath, "r", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i >= max_lines:
                        break
                    entry = self.parse_auto(line)
                    if entry:
                        entries.append(entry)
        except FileNotFoundError:
            logger.error(f"Log file not found: {filepath}")
        return entries


class TrafficMonitor:
    """
    Network traffic monitoring and analysis.
    Processes captured traffic data and stores in database.
    """

    def __init__(self):
        self._connection_tracker = {}  # IP -> {ports, count, timestamps}

    def process_packet(self, packet_data: dict, round_id=None) -> TrafficLog:
        """
        Process a network packet and store it.

        Args:
            packet_data: Dict with src_ip, dst_ip, src_port, dst_port, protocol, size, flags.
            round_id: Simulation round ID.

        Returns:
            TrafficLog instance.
        """
        log = TrafficLog.objects.create(
            source_ip=packet_data.get("src_ip", "0.0.0.0"),
            destination_ip=packet_data.get("dst_ip", "0.0.0.0"),
            source_port=packet_data.get("src_port"),
            destination_port=packet_data.get("dst_port"),
            protocol=packet_data.get("protocol", "TCP"),
            packet_size=packet_data.get("size", 0),
            flags=packet_data.get("flags", ""),
            payload_preview=packet_data.get("payload", "")[:500],
            round_id=round_id,
        )

        # Track connections per source IP
        src_ip = packet_data.get("src_ip", "")
        if src_ip:
            self._track_connection(src_ip, packet_data)

        return log

    def _track_connection(self, src_ip: str, packet_data: dict):
        """Track connection patterns for behavioral analysis."""
        if src_ip not in self._connection_tracker:
            self._connection_tracker[src_ip] = {
                "ports": set(),
                "count": 0,
                "first_seen": datetime.now(timezone.utc),
                "last_seen": datetime.now(timezone.utc),
            }

        tracker = self._connection_tracker[src_ip]
        tracker["count"] += 1
        tracker["last_seen"] = datetime.now(timezone.utc)
        if packet_data.get("dst_port"):
            tracker["ports"].add(packet_data["dst_port"])

    def get_connection_stats(self, source_ip: str) -> dict:
        """Get connection statistics for a source IP."""
        tracker = self._connection_tracker.get(source_ip, {})
        if not tracker:
            return {"connection_count": 0, "unique_ports": 0}

        duration = (tracker["last_seen"] - tracker["first_seen"]).total_seconds() or 1
        return {
            "connection_count": tracker["count"],
            "unique_ports": len(tracker.get("ports", set())),
            "ports": list(tracker.get("ports", set())),
            "packets_per_second": tracker["count"] / duration,
            "duration_seconds": duration,
        }

    def get_all_stats(self) -> dict:
        """Get traffic statistics across all monitored IPs."""
        stats = {}
        for ip, tracker in self._connection_tracker.items():
            stats[ip] = {
                "count": tracker["count"],
                "unique_ports": len(tracker.get("ports", set())),
            }
        return stats

    def reset(self):
        """Reset connection tracking (e.g. between simulation rounds)."""
        self._connection_tracker.clear()
