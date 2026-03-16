"""
Dashboard Views - Web frontend for the Cyber Battlefield
"""
import os
import io
import time
import threading
from django.core.management import call_command
from django.http import JsonResponse, StreamingHttpResponse
from django.shortcuts import render, redirect
from django.views import View
from django.conf import settings

from blue_team.models import Alert, DefenseAction, TrafficLog
from core.models import AgentAction, AIDecision, SystemEvent
from red_team.models import AttackPlan, ExploitAttempt, ScanResult, Vulnerability
from simulation.models import SimulationConfig, SimulationRound

class DashboardView(View):
    """Main dashboard overview."""

    def get(self, request):
        context = {
            "red_stats": {
                "total_scans": ScanResult.objects.count(),
                "completed_scans": ScanResult.objects.filter(status="completed").count(),
                "total_vulns": Vulnerability.objects.count(),
                "critical_vulns": Vulnerability.objects.filter(severity="critical").count(),
                "high_vulns": Vulnerability.objects.filter(severity="high").count(),
                "total_exploits": ExploitAttempt.objects.count(),
                "successful_exploits": ExploitAttempt.objects.filter(status="success").count(),
            },
            "blue_stats": {
                "total_alerts": Alert.objects.count(),
                "new_alerts": Alert.objects.filter(status="new").count(),
                "critical_alerts": Alert.objects.filter(severity="critical").count(),
                "total_actions": DefenseAction.objects.count(),
                "active_blocks": DefenseAction.objects.filter(
                    action_type="block_ip", status="active"
                ).count(),
                "total_traffic": TrafficLog.objects.count(),
                "anomalous_traffic": TrafficLog.objects.filter(is_anomalous=True).count(),
            },
            "simulation_stats": {
                "total_simulations": SimulationConfig.objects.count(),
                "running": SimulationConfig.objects.filter(status="running").count(),
                "completed": SimulationConfig.objects.filter(status="completed").count(),
                "total_rounds": SimulationRound.objects.count(),
            },
            "recent_actions": AgentAction.objects.all()[:15],
            "recent_alerts": Alert.objects.all()[:10],
            "recent_scans": ScanResult.objects.all()[:10],
        }
        return render(request, "dashboard/index.html", context)


class RedTeamDashboardView(View):
    def get(self, request):
        context = {
            "scans": ScanResult.objects.all()[:20],
            "vulnerabilities": Vulnerability.objects.select_related("scan").all()[:30],
            "exploits": ExploitAttempt.objects.all()[:20],
            "plans": AttackPlan.objects.all()[:10],
        }
        return render(request, "dashboard/red_team.html", context)


class BlueTeamDashboardView(View):
    def get(self, request):
        context = {
            "alerts": Alert.objects.all()[:30],
            "actions": DefenseAction.objects.select_related("alert").all()[:20],
            "traffic": TrafficLog.objects.filter(is_anomalous=True)[:20],
        }
        return render(request, "dashboard/blue_team.html", context)


class SimulationDashboardView(View):
    def get(self, request):
        context = {
            "simulations": SimulationConfig.objects.all()[:20],
            "recent_rounds": SimulationRound.objects.select_related("simulation").all()[:30],
        }
        return render(request, "dashboard/simulations.html", context)


class DashboardDataAPIView(View):
    """API endpoint for real-time dashboard data updates."""

    def get(self, request):
        # Recent round scores for charts
        rounds = SimulationRound.objects.filter(status="completed").order_by("-id")[:20]

        return JsonResponse({
            "red_team": {
                "scans": ScanResult.objects.count(),
                "vulns": Vulnerability.objects.count(),
                "exploits_success": ExploitAttempt.objects.filter(status="success").count(),
                "exploits_total": ExploitAttempt.objects.count(),
            },
            "blue_team": {
                "alerts": Alert.objects.count(),
                "blocks": DefenseAction.objects.filter(action_type="block_ip", status="active").count(),
                "detections": TrafficLog.objects.filter(is_anomalous=True).count(),
            },
            "round_scores": [
                {
                    "round": r.round_number,
                    "red": r.red_team_score,
                    "blue": r.blue_team_score,
                }
                for r in rounds
            ],
        })

class SimulationLogsView(View):
    def post(self, request):
        target_ip = request.POST.get("target_ip")
        max_rounds = request.POST.get("max_rounds", 5)

        if not target_ip:
            return redirect("dashboard:simulations")

        # Start the simulation background thread
        def run_sim():
            try:
                # Truncate real log to clear old simulation data
                log_file = settings.BASE_DIR / "logs/simulation.log"
                if log_file.exists():
                    open(log_file, 'w').close()
                    
                call_command("simulate", targets=[target_ip], rounds=int(max_rounds))
            except Exception as e:
                print(f"Simulation execution error: {e}")

        thread = threading.Thread(target=run_sim, daemon=True)
        thread.start()

        context = {
            "target_ip": target_ip,
            "max_rounds": max_rounds,
        }
        return render(request, "dashboard/simulation_logs.html", context)

    def get(self, request):
        return render(request, "dashboard/simulation_logs.html")

class SimulationStreamView(View):
    def get(self, request):
        def event_stream():
            log_file_path = settings.BASE_DIR / "logs/simulation.log"
            
            # If the log file doesn't exist yet, wait
            while not log_file_path.exists():
                time.sleep(1)

            with open(log_file_path, "r") as f:
                # Determine file size
                f.seek(0, os.SEEK_END)
                # Keep track of file position
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    yield f"data: {line}\n\n"

        response = StreamingHttpResponse(event_stream(), content_type="text/event-stream")
        response["Cache-Control"] = "no-cache"
        response["X-Accel-Buffering"] = "no" # For Nginx
        return response

