"""
Network Topology Simulator
============================
Defines virtual network topologies with subnets, segments,
firewalls, and routing for realistic battle simulation.
"""

import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("simulation.network")


class SegmentType(Enum):
    """Network segment types."""
    EXTERNAL = "external"
    DMZ = "dmz"
    INTERNAL = "internal"
    DATABASE = "database"
    MANAGEMENT = "management"
    IOT = "iot"
    CLOUD = "cloud"


class FirewallPolicy(Enum):
    ALLOW = "allow"
    DENY = "deny"
    RATE_LIMIT = "rate_limit"


@dataclass
class FirewallRule:
    """Firewall rule between segments."""
    source_segment: str
    dest_segment: str
    policy: FirewallPolicy = FirewallPolicy.DENY
    allowed_ports: list = field(default_factory=list)
    allowed_protocols: list = field(default_factory=lambda: ["TCP", "UDP"])
    description: str = ""
    enabled: bool = True

    def allows(self, port: int, protocol: str = "TCP") -> bool:
        """Check if this rule allows traffic on given port/protocol."""
        if not self.enabled:
            return False
        if self.policy == FirewallPolicy.DENY:
            return False
        if self.policy == FirewallPolicy.ALLOW:
            if not self.allowed_ports:  # No port restriction
                return protocol in self.allowed_protocols
            return port in self.allowed_ports and protocol in self.allowed_protocols
        return False


@dataclass
class NetworkHost:
    """A host in the virtual network."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    ip_address: str = ""
    hostname: str = ""
    os_type: str = "linux"  # linux, windows, network_device
    os_version: str = ""
    segment: str = ""
    services: list = field(default_factory=list)  # [{port, service, version, vulnerable}]
    users: list = field(default_factory=list)  # [{username, password_strength, privileges}]
    patches: list = field(default_factory=list)  # Applied patch IDs
    vulnerabilities: list = field(default_factory=list)  # [{cve, severity, exploitable}]
    is_compromised: bool = False
    compromise_level: str = ""  # "", "user", "root"
    is_honeypot: bool = False

    def get_open_ports(self) -> list:
        return [s["port"] for s in self.services]

    def has_service(self, service_name: str) -> bool:
        return any(s["service"] == service_name for s in self.services)

    def get_vulnerable_services(self) -> list:
        return [s for s in self.services if s.get("vulnerable")]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ip": self.ip_address,
            "hostname": self.hostname,
            "os": f"{self.os_type} {self.os_version}",
            "segment": self.segment,
            "services": len(self.services),
            "open_ports": self.get_open_ports(),
            "compromised": self.is_compromised,
            "compromise_level": self.compromise_level,
            "honeypot": self.is_honeypot,
        }


@dataclass
class NetworkSegment:
    """A network segment (subnet/VLAN)."""
    name: str
    segment_type: SegmentType
    cidr: str = ""
    hosts: list = field(default_factory=list)
    has_ids: bool = False
    has_firewall: bool = False
    visibility: float = 1.0  # Blue Team visibility (0.0 = blind, 1.0 = full)

    def add_host(self, host: NetworkHost):
        host.segment = self.name
        self.hosts.append(host)

    def get_host_by_ip(self, ip: str) -> Optional[NetworkHost]:
        for h in self.hosts:
            if h.ip_address == ip:
                return h
        return None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.segment_type.value,
            "cidr": self.cidr,
            "host_count": len(self.hosts),
            "has_ids": self.has_ids,
            "has_firewall": self.has_firewall,
            "visibility": self.visibility,
            "hosts": [h.to_dict() for h in self.hosts],
        }


class NetworkTopology:
    """
    Virtual network topology for simulation.
    Defines segments, hosts, firewall rules, and connectivity.

    Usage:
        topo = NetworkTopology("Corporate Network")
        dmz = topo.add_segment("DMZ", SegmentType.DMZ, "10.0.1.0/24")
        web_server = NetworkHost(ip_address="10.0.1.10", hostname="web01",
                                 services=[{"port": 80, "service": "http", "version": "Apache 2.4.49", "vulnerable": True}])
        dmz.add_host(web_server)
        topo.add_firewall_rule("external", "DMZ", FirewallPolicy.ALLOW, allowed_ports=[80, 443])
    """

    def __init__(self, name: str = "Default Network"):
        self.name = name
        self.id = str(uuid.uuid4())
        self.segments: dict[str, NetworkSegment] = {}
        self.firewall_rules: list[FirewallRule] = []
        self.routes: list[dict] = []  # [{from, to, latency_ms}]
        self._compromised_hosts: list[str] = []

    def add_segment(self, name: str, segment_type: SegmentType,
                    cidr: str = "", has_ids: bool = False,
                    has_firewall: bool = False,
                    visibility: float = 1.0) -> NetworkSegment:
        """Add a network segment."""
        segment = NetworkSegment(
            name=name,
            segment_type=segment_type,
            cidr=cidr,
            has_ids=has_ids,
            has_firewall=has_firewall,
            visibility=visibility,
        )
        self.segments[name] = segment
        logger.info(f"Network segment added: {name} ({segment_type.value}) {cidr}")
        return segment

    def add_firewall_rule(self, source: str, dest: str,
                          policy: FirewallPolicy,
                          allowed_ports: list = None,
                          description: str = "") -> FirewallRule:
        """Add a firewall rule between segments."""
        rule = FirewallRule(
            source_segment=source,
            dest_segment=dest,
            policy=policy,
            allowed_ports=allowed_ports or [],
            description=description,
        )
        self.firewall_rules.append(rule)
        return rule

    def add_route(self, from_segment: str, to_segment: str,
                  latency_ms: float = 1.0):
        """Add a route between segments."""
        self.routes.append({
            "from": from_segment,
            "to": to_segment,
            "latency_ms": latency_ms,
        })

    def can_reach(self, source_segment: str, dest_segment: str,
                  port: int, protocol: str = "TCP") -> bool:
        """Check if traffic can flow between segments on a given port."""
        # Same segment is always reachable
        if source_segment == dest_segment:
            return True

        # Check firewall rules
        for rule in self.firewall_rules:
            if (rule.source_segment == source_segment and
                    rule.dest_segment == dest_segment):
                return rule.allows(port, protocol)

        # Default: deny if no explicit rule exists
        return False

    def get_reachable_hosts(self, from_segment: str,
                            port: int = None) -> list:
        """Get all hosts reachable from a segment."""
        reachable = []
        for seg_name, segment in self.segments.items():
            if seg_name == from_segment:
                reachable.extend(segment.hosts)
                continue
            if port is None:
                # Check if any port is allowed
                for rule in self.firewall_rules:
                    if (rule.source_segment == from_segment and
                            rule.dest_segment == seg_name and
                            rule.policy != FirewallPolicy.DENY):
                        reachable.extend(segment.hosts)
                        break
            else:
                if self.can_reach(from_segment, seg_name, port):
                    reachable.extend(segment.hosts)
        return reachable

    def get_host_by_ip(self, ip: str) -> Optional[NetworkHost]:
        """Find a host by IP address across all segments."""
        for segment in self.segments.values():
            host = segment.get_host_by_ip(ip)
            if host:
                return host
        return None

    def get_segment_for_ip(self, ip: str) -> Optional[str]:
        """Find which segment an IP belongs to."""
        host = self.get_host_by_ip(ip)
        return host.segment if host else None

    def compromise_host(self, ip: str, level: str = "user") -> bool:
        """Mark a host as compromised."""
        host = self.get_host_by_ip(ip)
        if host:
            host.is_compromised = True
            host.compromise_level = level
            if ip not in self._compromised_hosts:
                self._compromised_hosts.append(ip)
            logger.warning(f"Host compromised: {ip} ({level} level)")
            return True
        return False

    def get_lateral_targets(self, compromised_ip: str) -> list:
        """Get hosts that can be reached from a compromised host (lateral movement)."""
        host = self.get_host_by_ip(compromised_ip)
        if not host:
            return []

        # Can reach everything in same segment
        same_segment = [
            h for h in self.segments.get(host.segment, NetworkSegment("", SegmentType.INTERNAL)).hosts
            if h.ip_address != compromised_ip
        ]

        # Also check adjacent segments via firewall rules
        adjacent = []
        for rule in self.firewall_rules:
            if rule.source_segment == host.segment and rule.policy != FirewallPolicy.DENY:
                seg = self.segments.get(rule.dest_segment)
                if seg:
                    adjacent.extend(seg.hosts)

        return same_segment + adjacent

    def get_compromised_hosts(self) -> list:
        """Get all compromised hosts."""
        return [
            self.get_host_by_ip(ip)
            for ip in self._compromised_hosts
            if self.get_host_by_ip(ip)
        ]

    def reset(self):
        """Reset all compromised hosts and dynamic state."""
        for ip in self._compromised_hosts:
            host = self.get_host_by_ip(ip)
            if host:
                host.is_compromised = False
                host.compromise_level = ""
        self._compromised_hosts.clear()

    def get_all_ips(self) -> list:
        """Get all IP addresses in the topology."""
        ips = []
        for segment in self.segments.values():
            for host in segment.hosts:
                ips.append(host.ip_address)
        return ips

    def to_dict(self) -> dict:
        """Serialize topology for API/dashboard use."""
        return {
            "id": self.id,
            "name": self.name,
            "segments": {k: v.to_dict() for k, v in self.segments.items()},
            "firewall_rules": [
                {
                    "source": r.source_segment,
                    "dest": r.dest_segment,
                    "policy": r.policy.value,
                    "ports": r.allowed_ports,
                    "enabled": r.enabled,
                }
                for r in self.firewall_rules
            ],
            "routes": self.routes,
            "total_hosts": sum(len(s.hosts) for s in self.segments.values()),
            "compromised_hosts": len(self._compromised_hosts),
        }


# ─── Pre-Built Topology Templates ──────────────────────────────────

def create_corporate_network() -> NetworkTopology:
    """
    Template: Standard corporate network.

    Internet → [FW] → DMZ (Web/Mail) → [FW+IDS] → Internal LAN → [FW] → DB Segment
                                                  → Management VLAN
    """
    topo = NetworkTopology("Corporate Network")

    # External (attacker origin)
    ext = topo.add_segment("external", SegmentType.EXTERNAL, "0.0.0.0/0")

    # DMZ - publicly facing
    dmz = topo.add_segment("dmz", SegmentType.DMZ, "10.0.1.0/24",
                           has_firewall=True, has_ids=True)
    dmz.add_host(NetworkHost(
        ip_address="10.0.1.10", hostname="web01", os_type="linux", os_version="Ubuntu 22.04",
        services=[
            {"port": 80, "service": "http", "version": "Apache 2.4.49", "vulnerable": True},
            {"port": 443, "service": "https", "version": "Apache 2.4.49", "vulnerable": True},
            {"port": 22, "service": "ssh", "version": "OpenSSH 8.9", "vulnerable": False},
        ],
        vulnerabilities=[{"cve": "CVE-2021-41773", "severity": "critical", "exploitable": True}],
    ))
    dmz.add_host(NetworkHost(
        ip_address="10.0.1.20", hostname="mail01", os_type="linux", os_version="CentOS 8",
        services=[
            {"port": 25, "service": "smtp", "version": "Postfix 3.5", "vulnerable": False},
            {"port": 110, "service": "pop3", "version": "Dovecot 2.3", "vulnerable": False},
            {"port": 143, "service": "imap", "version": "Dovecot 2.3", "vulnerable": False},
        ],
    ))

    # Internal LAN
    internal = topo.add_segment("internal", SegmentType.INTERNAL, "10.0.2.0/24",
                                has_ids=True, visibility=0.8)
    internal.add_host(NetworkHost(
        ip_address="10.0.2.10", hostname="workstation01", os_type="windows", os_version="Windows 10",
        services=[
            {"port": 445, "service": "smb", "version": "SMBv3", "vulnerable": True},
            {"port": 3389, "service": "rdp", "version": "RDP 10.0", "vulnerable": False},
        ],
        users=[
            {"username": "admin", "password_strength": "weak", "privileges": "admin"},
            {"username": "user01", "password_strength": "medium", "privileges": "user"},
        ],
        vulnerabilities=[{"cve": "CVE-2017-0144", "severity": "critical", "exploitable": True}],
    ))
    internal.add_host(NetworkHost(
        ip_address="10.0.2.20", hostname="fileserver01", os_type="linux", os_version="Ubuntu 20.04",
        services=[
            {"port": 21, "service": "ftp", "version": "vsftpd 3.0.3", "vulnerable": True},
            {"port": 22, "service": "ssh", "version": "OpenSSH 7.4", "vulnerable": True},
            {"port": 445, "service": "smb", "version": "Samba 4.11", "vulnerable": False},
        ],
        vulnerabilities=[{"cve": "CVE-2024-1234", "severity": "high", "exploitable": True}],
    ))

    # Database segment
    db = topo.add_segment("database", SegmentType.DATABASE, "10.0.3.0/24",
                          has_firewall=True, visibility=0.6)
    db.add_host(NetworkHost(
        ip_address="10.0.3.10", hostname="db01", os_type="linux", os_version="RHEL 8",
        services=[
            {"port": 3306, "service": "mysql", "version": "MySQL 8.0", "vulnerable": False},
            {"port": 22, "service": "ssh", "version": "OpenSSH 8.0", "vulnerable": False},
        ],
    ))
    db.add_host(NetworkHost(
        ip_address="10.0.3.20", hostname="db02", os_type="linux", os_version="RHEL 8",
        services=[
            {"port": 5432, "service": "postgresql", "version": "PostgreSQL 14", "vulnerable": True},
        ],
        vulnerabilities=[{"cve": "CVE-2023-5678", "severity": "high", "exploitable": True}],
    ))

    # Management VLAN
    mgmt = topo.add_segment("management", SegmentType.MANAGEMENT, "10.0.10.0/24",
                            has_firewall=True, has_ids=True, visibility=1.0)
    mgmt.add_host(NetworkHost(
        ip_address="10.0.10.10", hostname="siem01", os_type="linux", os_version="Ubuntu 22.04",
        services=[
            {"port": 9200, "service": "elasticsearch", "version": "8.11", "vulnerable": False},
            {"port": 5601, "service": "kibana", "version": "8.11", "vulnerable": False},
        ],
    ))

    # Firewall rules
    topo.add_firewall_rule("external", "dmz", FirewallPolicy.ALLOW,
                           allowed_ports=[80, 443, 25], description="Public access to DMZ")
    topo.add_firewall_rule("dmz", "internal", FirewallPolicy.ALLOW,
                           allowed_ports=[22, 445], description="DMZ to Internal (limited)")
    topo.add_firewall_rule("internal", "database", FirewallPolicy.ALLOW,
                           allowed_ports=[3306, 5432], description="Internal to DB")
    topo.add_firewall_rule("internal", "management", FirewallPolicy.DENY,
                           description="No direct access to management")
    topo.add_firewall_rule("management", "internal", FirewallPolicy.ALLOW,
                           description="Management can access internal")
    topo.add_firewall_rule("management", "dmz", FirewallPolicy.ALLOW,
                           description="Management can access DMZ")

    # Routes
    topo.add_route("external", "dmz", latency_ms=5.0)
    topo.add_route("dmz", "internal", latency_ms=1.0)
    topo.add_route("internal", "database", latency_ms=0.5)
    topo.add_route("internal", "management", latency_ms=1.0)

    logger.info(f"Corporate network topology created: {sum(len(s.hosts) for s in topo.segments.values())} hosts")
    return topo


def create_hospital_network() -> NetworkTopology:
    """Template: Hospital network with medical devices and SCADA."""
    topo = NetworkTopology("Hospital Network")

    ext = topo.add_segment("external", SegmentType.EXTERNAL, "0.0.0.0/0")
    dmz = topo.add_segment("dmz", SegmentType.DMZ, "172.16.1.0/24",
                           has_firewall=True, has_ids=True)
    dmz.add_host(NetworkHost(
        ip_address="172.16.1.10", hostname="portal", os_type="linux",
        services=[
            {"port": 443, "service": "https", "version": "Nginx 1.18", "vulnerable": True},
        ],
        vulnerabilities=[{"cve": "CVE-2023-1234", "severity": "high", "exploitable": True}],
    ))

    clinical = topo.add_segment("clinical", SegmentType.INTERNAL, "172.16.2.0/24",
                                has_ids=True, visibility=0.7)
    clinical.add_host(NetworkHost(
        ip_address="172.16.2.10", hostname="ehr-server", os_type="windows", os_version="Server 2019",
        services=[
            {"port": 443, "service": "https", "version": "IIS 10", "vulnerable": False},
            {"port": 1433, "service": "mssql", "version": "SQL Server 2019", "vulnerable": True},
        ],
    ))

    iot = topo.add_segment("medical_iot", SegmentType.IOT, "172.16.5.0/24",
                           visibility=0.3)
    iot.add_host(NetworkHost(
        ip_address="172.16.5.10", hostname="infusion-pump-01", os_type="embedded",
        services=[{"port": 80, "service": "http", "version": "Custom 1.0", "vulnerable": True}],
        vulnerabilities=[{"cve": "CVE-2022-9999", "severity": "critical", "exploitable": True}],
    ))
    iot.add_host(NetworkHost(
        ip_address="172.16.5.20", hostname="monitor-01", os_type="embedded",
        services=[{"port": 8080, "service": "http", "version": "Custom 2.0", "vulnerable": True}],
    ))

    db = topo.add_segment("database", SegmentType.DATABASE, "172.16.3.0/24",
                          has_firewall=True, visibility=0.9)
    db.add_host(NetworkHost(
        ip_address="172.16.3.10", hostname="patient-db", os_type="linux",
        services=[{"port": 3306, "service": "mysql", "version": "MySQL 8.0", "vulnerable": False}],
    ))

    topo.add_firewall_rule("external", "dmz", FirewallPolicy.ALLOW, allowed_ports=[443])
    topo.add_firewall_rule("dmz", "clinical", FirewallPolicy.ALLOW, allowed_ports=[443])
    topo.add_firewall_rule("clinical", "database", FirewallPolicy.ALLOW, allowed_ports=[3306, 1433])
    topo.add_firewall_rule("clinical", "medical_iot", FirewallPolicy.ALLOW, allowed_ports=[80, 8080])

    return topo


def create_cloud_infrastructure() -> NetworkTopology:
    """Template: Multi-tier cloud infrastructure."""
    topo = NetworkTopology("Cloud Infrastructure")

    ext = topo.add_segment("internet", SegmentType.EXTERNAL, "0.0.0.0/0")

    lb = topo.add_segment("load_balancer", SegmentType.DMZ, "10.10.0.0/24",
                          has_firewall=True, has_ids=True)
    lb.add_host(NetworkHost(
        ip_address="10.10.0.10", hostname="alb-01", os_type="network_device",
        services=[
            {"port": 80, "service": "http", "version": "ALB", "vulnerable": False},
            {"port": 443, "service": "https", "version": "ALB", "vulnerable": False},
        ],
    ))

    app = topo.add_segment("application", SegmentType.INTERNAL, "10.10.1.0/24",
                           has_ids=True, visibility=0.9)
    for i in range(3):
        app.add_host(NetworkHost(
            ip_address=f"10.10.1.{10+i}", hostname=f"app-{i+1:02d}",
            os_type="linux", os_version="Ubuntu 22.04",
            services=[
                {"port": 8080, "service": "http", "version": "Node.js 18", "vulnerable": i == 0},
                {"port": 22, "service": "ssh", "version": "OpenSSH 9.0", "vulnerable": False},
            ],
        ))

    cache = topo.add_segment("cache", SegmentType.INTERNAL, "10.10.2.0/24", visibility=0.5)
    cache.add_host(NetworkHost(
        ip_address="10.10.2.10", hostname="redis-01", os_type="linux",
        services=[{"port": 6379, "service": "redis", "version": "Redis 7.2", "vulnerable": True}],
        vulnerabilities=[{"cve": "CVE-2023-2222", "severity": "high", "exploitable": True}],
    ))

    db = topo.add_segment("database", SegmentType.DATABASE, "10.10.3.0/24",
                          has_firewall=True, visibility=0.8)
    db.add_host(NetworkHost(
        ip_address="10.10.3.10", hostname="rds-primary", os_type="linux",
        services=[{"port": 5432, "service": "postgresql", "version": "15", "vulnerable": False}],
    ))

    topo.add_firewall_rule("internet", "load_balancer", FirewallPolicy.ALLOW, allowed_ports=[80, 443])
    topo.add_firewall_rule("load_balancer", "application", FirewallPolicy.ALLOW, allowed_ports=[8080])
    topo.add_firewall_rule("application", "cache", FirewallPolicy.ALLOW, allowed_ports=[6379])
    topo.add_firewall_rule("application", "database", FirewallPolicy.ALLOW, allowed_ports=[5432])

    return topo


# Registry of available templates
TOPOLOGY_TEMPLATES = {
    "corporate": create_corporate_network,
    "hospital": create_hospital_network,
    "cloud": create_cloud_infrastructure,
}
