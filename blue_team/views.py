"""
Blue Team API Views
"""

import json
import threading

from django.http import JsonResponse
from django.views import View

from blue_team.agent import BlueTeamAgent
from blue_team.models import Alert, DefenseAction, DetectionRule, TrafficLog


class AlertListView(View):
    def get(self, request):
        severity = request.GET.get("severity")
        status = request.GET.get("status")

        alerts = Alert.objects.all()
        if severity:
            alerts = alerts.filter(severity=severity)
        if status:
            alerts = alerts.filter(status=status)

        return JsonResponse({
            "alerts": [
                {
                    "id": str(a.id),
                    "severity": a.severity,
                    "source": a.source,
                    "status": a.status,
                    "title": a.title,
                    "source_ip": a.source_ip,
                    "destination_ip": a.destination_ip,
                    "destination_port": a.destination_port,
                    "confidence": a.confidence,
                    "created_at": a.created_at.isoformat(),
                }
                for a in alerts[:100]
            ]
        })


class DefenseActionListView(View):
    def get(self, request):
        actions = DefenseAction.objects.select_related("alert").all()[:100]
        return JsonResponse({
            "actions": [
                {
                    "id": str(a.id),
                    "action_type": a.action_type,
                    "status": a.status,
                    "target_ip": a.target_ip,
                    "reasoning": a.reasoning,
                    "confidence": a.confidence,
                    "auto_generated": a.auto_generated,
                    "created_at": a.created_at.isoformat(),
                }
                for a in actions
            ]
        })


class TrafficLogView(View):
    def get(self, request):
        anomalous_only = request.GET.get("anomalous", "false").lower() == "true"
        logs = TrafficLog.objects.all()
        if anomalous_only:
            logs = logs.filter(is_anomalous=True)

        return JsonResponse({
            "traffic": [
                {
                    "id": str(t.id),
                    "source_ip": t.source_ip,
                    "destination_ip": t.destination_ip,
                    "source_port": t.source_port,
                    "destination_port": t.destination_port,
                    "protocol": t.protocol,
                    "packet_size": t.packet_size,
                    "is_anomalous": t.is_anomalous,
                    "anomaly_score": t.anomaly_score,
                    "timestamp": t.timestamp.isoformat(),
                }
                for t in logs[:200]
            ]
        })


class DetectionRuleListView(View):
    def get(self, request):
        rules = DetectionRule.objects.all()
        return JsonResponse({
            "rules": [
                {
                    "id": str(r.id),
                    "name": r.name,
                    "rule_type": r.rule_type,
                    "enabled": r.enabled,
                    "hit_count": r.hit_count,
                    "false_positive_count": r.false_positive_count,
                    "auto_generated": r.auto_generated,
                }
                for r in rules
            ]
        })


class RunDefenseView(View):
    def post(self, request):
        agent = BlueTeamAgent()

        def run_defense():
            agent.monitor_and_defend()

        thread = threading.Thread(target=run_defense, daemon=True)
        thread.start()

        return JsonResponse({"status": "defense_cycle_started", "agent": agent.name})


class BlueTeamStatusView(View):
    def get(self, request):
        agent = BlueTeamAgent()
        return JsonResponse(agent.get_status())
