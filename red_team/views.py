"""
Red Team API Views
"""

import threading

from django.http import JsonResponse
from django.views import View

from red_team.agent import RedTeamAgent
from red_team.models import AttackPlan, ExploitAttempt, ScanResult, Vulnerability


class StartScanView(View):
    """Start a new scan against a target."""

    def post(self, request):
        import json
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            data = {}

        target_ip = data.get("target_ip", "")
        port_range = data.get("port_range", "1-10000")
        scan_type = data.get("scan_type", "tcp")

        if not target_ip:
            return JsonResponse({"error": "target_ip is required"}, status=400)

        from red_team.recon.scanner import ReconScanner
        scanner = ReconScanner()

        # Run scan in background thread
        def run_scan():
            scanner.nmap_scan(target_ip, port_range, scan_type)

        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()

        return JsonResponse({
            "status": "scan_started",
            "target_ip": target_ip,
            "scan_type": scan_type,
        })


class ScanListView(View):
    """List all scan results."""

    def get(self, request):
        scans = ScanResult.objects.all()[:50]
        return JsonResponse({
            "scans": [
                {
                    "id": str(s.id),
                    "scan_type": s.scan_type,
                    "target_ip": s.target_ip,
                    "status": s.status,
                    "open_ports_count": len(s.open_ports) if s.open_ports else 0,
                    "duration_seconds": s.duration_seconds,
                    "created_at": s.created_at.isoformat(),
                }
                for s in scans
            ]
        })


class ScanDetailView(View):
    """Get detailed scan results."""

    def get(self, request, scan_id):
        try:
            scan = ScanResult.objects.get(id=scan_id)
        except ScanResult.DoesNotExist:
            return JsonResponse({"error": "Scan not found"}, status=404)

        vulns = Vulnerability.objects.filter(scan=scan)
        return JsonResponse({
            "id": str(scan.id),
            "scan_type": scan.scan_type,
            "target_ip": scan.target_ip,
            "status": scan.status,
            "open_ports": scan.open_ports,
            "services": scan.services,
            "os_detection": scan.os_detection,
            "duration_seconds": scan.duration_seconds,
            "created_at": scan.created_at.isoformat(),
            "vulnerabilities": [
                {
                    "id": str(v.id),
                    "cve_id": v.cve_id,
                    "title": v.title,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "exploitable": v.exploitable,
                }
                for v in vulns
            ],
        })


class VulnerabilityListView(View):
    """List all discovered vulnerabilities."""

    def get(self, request):
        vulns = Vulnerability.objects.select_related("scan").all()[:100]
        return JsonResponse({
            "vulnerabilities": [
                {
                    "id": str(v.id),
                    "cve_id": v.cve_id,
                    "title": v.title,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "affected_service": v.affected_service,
                    "affected_port": v.affected_port,
                    "target_ip": v.scan.target_ip,
                    "exploitable": v.exploitable,
                    "created_at": v.created_at.isoformat(),
                }
                for v in vulns
            ]
        })


class LaunchAttackView(View):
    """Launch a full attack cycle against a target."""

    def post(self, request):
        import json
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            data = {}

        target_ip = data.get("target_ip", "")
        if not target_ip:
            return JsonResponse({"error": "target_ip is required"}, status=400)

        agent = RedTeamAgent()

        # Run attack in background
        result_holder = {"result": None}

        def run_attack():
            result_holder["result"] = agent.run_full_attack(target_ip)

        thread = threading.Thread(target=run_attack, daemon=True)
        thread.start()

        return JsonResponse({
            "status": "attack_started",
            "target_ip": target_ip,
            "agent": agent.name,
        })


class AttackPlanListView(View):
    """List attack plans."""

    def get(self, request):
        plans = AttackPlan.objects.all()[:50]
        return JsonResponse({
            "plans": [
                {
                    "id": str(p.id),
                    "target_ip": p.target_ip,
                    "total_steps": p.total_steps,
                    "completed_steps": p.completed_steps,
                    "success_rate": p.success_rate,
                    "created_at": p.created_at.isoformat(),
                }
                for p in plans
            ]
        })


class ExploitListView(View):
    """List exploit attempts."""

    def get(self, request):
        attempts = ExploitAttempt.objects.all()[:50]
        return JsonResponse({
            "exploits": [
                {
                    "id": str(a.id),
                    "exploit_type": a.exploit_type,
                    "target_ip": a.target_ip,
                    "target_port": a.target_port,
                    "status": a.status,
                    "session_obtained": a.session_obtained,
                    "created_at": a.created_at.isoformat(),
                }
                for a in attempts
            ]
        })


class RedTeamStatusView(View):
    """Get Red Team agent status."""

    def get(self, request):
        from core.safety import get_safety_module
        safety = get_safety_module()

        return JsonResponse({
            "agent": "RedTeamAgent",
            "status": "ready",
            "safety": safety.get_status(),
            "stats": {
                "total_scans": ScanResult.objects.count(),
                "completed_scans": ScanResult.objects.filter(status="completed").count(),
                "total_vulnerabilities": Vulnerability.objects.count(),
                "critical_vulns": Vulnerability.objects.filter(severity="critical").count(),
                "total_exploits": ExploitAttempt.objects.count(),
                "successful_exploits": ExploitAttempt.objects.filter(status="success").count(),
            },
        })
