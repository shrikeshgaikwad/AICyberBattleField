"""
Dashboard Views - Web frontend for the Cyber Battlefield
"""

from django.http import JsonResponse
from django.shortcuts import render
from django.views import View

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
