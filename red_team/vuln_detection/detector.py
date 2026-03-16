"""
Vulnerability Detector - CVE Mapping + LLM Analysis
=====================================================
Two-stage vulnerability detection from scan results.
"""

import logging
from typing import Optional

from core.event_bus import Event, EventType, get_event_bus
from core.llm_client import LLMClient
from red_team.models import ScanResult, Vulnerability

logger = logging.getLogger("red_team.vuln_detection")

# Common CVE mappings for known service versions
KNOWN_CVES = {
    "apache": {
        "2.4.49": [{"cve": "CVE-2021-41773", "severity": "critical", "title": "Apache Path Traversal & RCE", "cvss": 9.8}],
        "2.4.50": [{"cve": "CVE-2021-42013", "severity": "critical", "title": "Apache Path Traversal Bypass", "cvss": 9.8}],
    },
    "openssh": {
        "7.": [{"cve": "CVE-2018-15473", "severity": "medium", "title": "OpenSSH User Enumeration", "cvss": 5.3}],
    },
    "mysql": {
        "5.5": [{"cve": "CVE-2012-2122", "severity": "high", "title": "MySQL Auth Bypass", "cvss": 7.5}],
        "5.6": [{"cve": "CVE-2012-2122", "severity": "high", "title": "MySQL Auth Bypass", "cvss": 7.5}],
    },
    "postgresql": {
        "9.": [{"cve": "CVE-2019-9193", "severity": "high", "title": "PostgreSQL RCE via COPY", "cvss": 8.8}],
    },
    "smb": {
        "1": [{"cve": "CVE-2017-0144", "severity": "critical", "title": "EternalBlue SMBv1 RCE", "cvss": 9.8}],
    },
    "vsftpd": {
        "2.3.4": [{"cve": "CVE-2011-2523", "severity": "critical", "title": "vsftpd 2.3.4 Backdoor", "cvss": 10.0}],
    },
    "proftpd": {
        "1.3.5": [{"cve": "CVE-2015-3306", "severity": "critical", "title": "ProFTPD mod_copy RCE", "cvss": 10.0}],
    },
}

VULN_ANALYSIS_PROMPT = """You are an expert cybersecurity vulnerability analyst. Analyze the following scan results and identify potential vulnerabilities.

For each vulnerability found, provide:
1. A CVE ID if known (or "N/A")
2. Title of the vulnerability
3. Severity: critical, high, medium, low, or info
4. CVSS score (0.0-10.0)
5. The affected service and port
6. A brief description
7. Whether it's likely exploitable (true/false)
8. Recommended remediation

Respond in JSON format:
{
  "vulnerabilities": [
    {
      "cve_id": "CVE-XXXX-XXXX",
      "title": "...",
      "severity": "high",
      "cvss_score": 7.5,
      "affected_service": "...",
      "affected_port": 80,
      "description": "...",
      "exploitable": true,
      "remediation": "..."
    }
  ],
  "summary": "Brief overall assessment"
}
"""


class VulnerabilityDetector:
    """
    Detects vulnerabilities through CVE pattern matching and LLM analysis.
    """

    def __init__(self):
        self.llm = LLMClient()
        self.event_bus = get_event_bus()

    def detect(self, scan: ScanResult, round_id=None) -> list:
        """
        Run full vulnerability detection on scan results.

        1. Pattern-match known CVEs against discovered services
        2. Send to LLM for deeper analysis

        Returns list of created Vulnerability instances.
        """
        vulnerabilities = []

        # Stage 1: CVE Pattern Matching
        cve_vulns = self._cve_pattern_match(scan, round_id)
        vulnerabilities.extend(cve_vulns)

        # Stage 2: LLM Analysis
        llm_vulns = self._llm_analysis(scan, round_id)
        vulnerabilities.extend(llm_vulns)

        logger.info(f"Detected {len(vulnerabilities)} vulnerabilities for scan {scan.id}")

        # Publish events
        for vuln in vulnerabilities:
            self.event_bus.publish(Event(
                event_type=EventType.VULNERABILITY_FOUND,
                source="red_team.vuln_detection",
                data={
                    "vulnerability_id": str(vuln.id),
                    "cve_id": vuln.cve_id,
                    "severity": vuln.severity,
                    "title": vuln.title,
                    "target": scan.target_ip,
                    "port": vuln.affected_port,
                },
            ))

        return vulnerabilities

    def _cve_pattern_match(self, scan: ScanResult, round_id=None) -> list:
        """Match discovered services against known CVE database."""
        vulns = []

        for service in scan.services:
            service_name = (service.get("name", "") or "").lower()
            product = (service.get("product", "") or "").lower()
            version = service.get("version", "") or ""
            port = service.get("port")

            # Try matching
            for key, version_map in KNOWN_CVES.items():
                if key in service_name or key in product:
                    for ver_prefix, cve_list in version_map.items():
                        if version.startswith(ver_prefix):
                            for cve_info in cve_list:
                                vuln = Vulnerability.objects.create(
                                    scan=scan,
                                    cve_id=cve_info["cve"],
                                    title=cve_info["title"],
                                    severity=cve_info["severity"],
                                    cvss_score=cve_info.get("cvss"),
                                    affected_service=f"{product} {version}".strip(),
                                    affected_port=port,
                                    detection_method=Vulnerability.DetectionMethod.CVE_MATCH,
                                    confidence=0.85,
                                    exploitable=True,
                                    round_id=round_id,
                                )
                                vulns.append(vuln)
                                logger.info(f"CVE match: {cve_info['cve']} on port {port}")

        return vulns

    def _llm_analysis(self, scan: ScanResult, round_id=None) -> list:
        """Use LLM to analyze scan results for vulnerabilities."""
        vulns = []

        # Build scan summary for LLM
        scan_summary = self._build_scan_summary(scan)
        if not scan_summary:
            return vulns

        response = self.llm.query_json(
            user_prompt=f"Analyze these scan results:\n\n{scan_summary}",
            system_prompt=VULN_ANALYSIS_PROMPT,
            temperature=0.3,
        )

        if not response or "vulnerabilities" not in response:
            logger.warning("LLM vulnerability analysis returned no results")
            return vulns

        for v in response["vulnerabilities"]:
            try:
                # Avoid duplicating CVEs already found by pattern matching
                cve_id = v.get("cve_id", "N/A")
                if cve_id != "N/A" and Vulnerability.objects.filter(scan=scan, cve_id=cve_id).exists():
                    continue

                vuln = Vulnerability.objects.create(
                    scan=scan,
                    cve_id=cve_id if cve_id != "N/A" else "",
                    title=v.get("title", "Unknown Vulnerability"),
                    description=v.get("description", ""),
                    severity=v.get("severity", "medium"),
                    cvss_score=v.get("cvss_score"),
                    affected_service=v.get("affected_service", ""),
                    affected_port=v.get("affected_port"),
                    detection_method=Vulnerability.DetectionMethod.LLM_ANALYSIS,
                    confidence=0.6,
                    remediation=v.get("remediation", ""),
                    exploitable=v.get("exploitable", False),
                    round_id=round_id,
                    raw_evidence=v,
                )
                vulns.append(vuln)
            except Exception as e:
                logger.warning(f"Failed to create vulnerability from LLM data: {e}")

        return vulns

    def _build_scan_summary(self, scan: ScanResult) -> str:
        """Build a human-readable summary of scan results for LLM input."""
        lines = [
            f"Target: {scan.target_ip}",
            f"Scan Type: {scan.scan_type}",
            f"Open Ports ({len(scan.open_ports)}):",
        ]

        for port in scan.open_ports:
            lines.append(
                f"  - Port {port['port']}/{port.get('protocol', 'tcp')}: "
                f"{port.get('service', 'unknown')} "
                f"({port.get('product', '')} {port.get('version', '')})"
            )

        if scan.services:
            lines.append(f"\nServices ({len(scan.services)}):")
            for svc in scan.services:
                lines.append(
                    f"  - {svc.get('name', 'unknown')}: "
                    f"{svc.get('product', '')} {svc.get('version', '')}"
                )

        if scan.os_detection:
            lines.append(f"\nOS Detection: {scan.os_detection}")

        return "\n".join(lines)
