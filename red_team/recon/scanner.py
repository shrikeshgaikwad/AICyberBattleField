"""
Reconnaissance Scanner - Nmap, Nikto, and Gobuster Wrappers
=============================================================
Provides unified scanning interface with structured output.
"""

import logging
import subprocess
import time
from typing import Optional

from django.utils import timezone

from core.event_bus import Event, EventType, get_event_bus
from core.safety import get_safety_module
from red_team.models import ScanResult

logger = logging.getLogger("red_team.recon")


class ReconScanner:
    """
    Unified reconnaissance scanner wrapping nmap, nikto, and gobuster.
    Stores results in the database and publishes events.
    """

    def __init__(self):
        self.safety = get_safety_module()
        self.event_bus = get_event_bus()

    def nmap_scan(
        self,
        target_ip: str,
        port_range: str = "1-10000",
        scan_type: str = "tcp",
        round_id=None,
    ) -> Optional[ScanResult]:
        """
        Run an nmap scan against a target.

        Args:
            target_ip: Target IP address.
            port_range: Port range to scan (e.g. '1-1000', '80,443,8080').
            scan_type: 'tcp', 'udp', or 'vuln'.
            round_id: Simulation round ID.

        Returns:
            ScanResult model instance or None on failure.
        """
        # Safety check
        if not self.safety.validate_target(target_ip):
            logger.warning(f"Target {target_ip} rejected by safety module")
            return None

        scan_type_choice = {
            "tcp": ScanResult.ScanType.NMAP_TCP,
            "udp": ScanResult.ScanType.NMAP_UDP,
            "vuln": ScanResult.ScanType.NMAP_VULN,
        }.get(scan_type, ScanResult.ScanType.NMAP_TCP)

        # Create scan record
        scan = ScanResult.objects.create(
            scan_type=scan_type_choice,
            target_ip=target_ip,
            target_port_range=port_range,
            status=ScanResult.Status.RUNNING,
            round_id=round_id,
        )

        self.event_bus.publish(Event(
            event_type=EventType.SCAN_STARTED,
            source="red_team.recon",
            data={"scan_id": str(scan.id), "target": target_ip, "type": scan_type},
        ))

        try:
            start_time = time.time()
            results = self._run_nmap(target_ip, port_range, scan_type)
            duration = time.time() - start_time

            scan.results = results.get("raw", {})
            scan.open_ports = results.get("open_ports", [])
            scan.services = results.get("services", [])
            scan.os_detection = results.get("os_detection", {})
            scan.status = ScanResult.Status.COMPLETED
            scan.duration_seconds = duration
            scan.completed_at = timezone.now()
            scan.save()

            logger.info(
                f"Nmap scan completed: {target_ip} - "
                f"{len(scan.open_ports)} open ports found in {duration:.1f}s"
            )

            self.event_bus.publish(Event(
                event_type=EventType.SCAN_COMPLETED,
                source="red_team.recon",
                data={
                    "scan_id": str(scan.id),
                    "target": target_ip,
                    "open_ports_count": len(scan.open_ports),
                    "services_count": len(scan.services),
                },
            ))

            return scan

        except Exception as e:
            scan.status = ScanResult.Status.FAILED
            scan.error_message = str(e)
            scan.completed_at = timezone.now()
            scan.save()
            logger.error(f"Nmap scan failed for {target_ip}: {e}", exc_info=True)
            return scan

    def _run_nmap(self, target_ip: str, port_range: str, scan_type: str) -> dict:
        """Execute nmap and parse results."""
        try:
            import nmap
            nm = nmap.PortScanner()
        except ImportError:
            logger.warning("python-nmap not installed, using subprocess fallback")
            return self._run_nmap_subprocess(target_ip, port_range, scan_type)

        # Build scan arguments
        args = f"-p {port_range} -sV"
        if scan_type == "udp":
            args = f"-p {port_range} -sU -sV"
        elif scan_type == "vuln":
            args = f"-p {port_range} -sV --script=vuln"

        logger.info(f"Running nmap: nmap {args} {target_ip}")
        nm.scan(target_ip, arguments=args)

        open_ports = []
        services = []

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    port_info = nm[host][proto][port]
                    port_data = {
                        "port": port,
                        "protocol": proto,
                        "state": port_info.get("state", "unknown"),
                        "service": port_info.get("name", "unknown"),
                        "version": port_info.get("version", ""),
                        "product": port_info.get("product", ""),
                        "extra_info": port_info.get("extrainfo", ""),
                    }

                    if port_info.get("state") == "open":
                        open_ports.append(port_data)

                    services.append({
                        "port": port,
                        "name": port_info.get("name", "unknown"),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "extra_info": port_info.get("extrainfo", ""),
                    })

        os_detection = {}
        try:
            if nm[target_ip].get("osmatch"):
                os_detection = {
                    "matches": [
                        {"name": m["name"], "accuracy": m["accuracy"]}
                        for m in nm[target_ip]["osmatch"][:3]
                    ]
                }
        except (KeyError, IndexError):
            pass

        return {
            "raw": dict(nm[target_ip]) if target_ip in nm.all_hosts() else {},
            "open_ports": open_ports,
            "services": services,
            "os_detection": os_detection,
        }

    def _run_nmap_subprocess(self, target_ip: str, port_range: str, scan_type: str) -> dict:
        """Fallback: run nmap via subprocess when python-nmap is unavailable."""
        cmd = ["nmap", "-p", port_range, "-sV", "--open", "-oX", "-", target_ip]
        if scan_type == "udp":
            cmd = ["nmap", "-p", port_range, "-sU", "-sV", "--open", "-oX", "-", target_ip]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                logger.warning(f"Nmap subprocess error: {result.stderr}")

            # Parse XML output (simplified)
            open_ports = []
            for line in result.stdout.split("\n"):
                if "open" in line and "port" not in line.lower().startswith("port"):
                    parts = line.strip().split()
                    if parts and "/" in parts[0]:
                        port_proto = parts[0].split("/")
                        open_ports.append({
                            "port": int(port_proto[0]),
                            "protocol": port_proto[1] if len(port_proto) > 1 else "tcp",
                            "state": "open",
                            "service": parts[2] if len(parts) > 2 else "unknown",
                        })

            return {"raw": {"stdout": result.stdout}, "open_ports": open_ports, "services": [], "os_detection": {}}
        except FileNotFoundError:
            logger.error("nmap is not installed on this system")
            return {"raw": {}, "open_ports": [], "services": [], "os_detection": {}}
        except subprocess.TimeoutExpired:
            logger.error("nmap scan timed out")
            return {"raw": {}, "open_ports": [], "services": [], "os_detection": {}}

    def nikto_scan(self, target_url: str, round_id=None) -> Optional[ScanResult]:
        """Run a Nikto web vulnerability scan."""
        # Extract IP from URL
        from urllib.parse import urlparse
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        target_ip = parsed.hostname or target_url

        if not self.safety.validate_target(target_ip):
            return None

        scan = ScanResult.objects.create(
            scan_type=ScanResult.ScanType.NIKTO,
            target_ip=target_ip,
            status=ScanResult.Status.RUNNING,
            round_id=round_id,
        )

        try:
            start_time = time.time()
            cmd = ["nikto", "-h", target_url, "-Format", "json", "-output", "-"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            duration = time.time() - start_time

            scan.results = {"stdout": result.stdout, "stderr": result.stderr}
            scan.status = ScanResult.Status.COMPLETED
            scan.duration_seconds = duration
            scan.completed_at = timezone.now()
            scan.save()

            logger.info(f"Nikto scan completed for {target_url} in {duration:.1f}s")
            return scan

        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            scan.status = ScanResult.Status.FAILED
            scan.error_message = str(e)
            scan.save()
            return scan

    def gobuster_scan(self, target_url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", round_id=None) -> Optional[ScanResult]:
        """Run a Gobuster directory brute-force scan."""
        from urllib.parse import urlparse
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        target_ip = parsed.hostname or target_url

        if not self.safety.validate_target(target_ip):
            return None

        scan = ScanResult.objects.create(
            scan_type=ScanResult.ScanType.GOBUSTER,
            target_ip=target_ip,
            status=ScanResult.Status.RUNNING,
            round_id=round_id,
        )

        try:
            start_time = time.time()
            cmd = ["gobuster", "dir", "-u", target_url, "-w", wordlist, "-q", "--no-color"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            duration = time.time() - start_time

            directories = []
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    directories.append(line.strip())

            scan.results = {"directories": directories, "stdout": result.stdout}
            scan.status = ScanResult.Status.COMPLETED
            scan.duration_seconds = duration
            scan.completed_at = timezone.now()
            scan.save()

            logger.info(f"Gobuster scan completed for {target_url}: {len(directories)} dirs found")
            return scan

        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            scan.status = ScanResult.Status.FAILED
            scan.error_message = str(e)
            scan.save()
            return scan
