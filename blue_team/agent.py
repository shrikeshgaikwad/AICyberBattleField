"""
Blue Team Agent - Defense Orchestrator
========================================
Implements the full defense lifecycle:
Monitor → Detect → Classify → Respond → Learn → Adapt
"""

import logging
import time
from typing import Optional

from core.event_bus import Event, EventType, get_event_bus
from core.logger import AgentLogger
from core.models import AgentAction, AIDecision
from blue_team.detection.anomaly import AnomalyDetector
from blue_team.detection.signatures import SignatureDetector
from blue_team.models import Alert, DefenseAction, TrafficLog
from blue_team.monitoring.log_parser import LogParser, TrafficMonitor
from blue_team.response.engine import ResponseEngine

logger = logging.getLogger("blue_team")


class BlueTeamAgent:
    """
    Autonomous defensive AI agent.
    Orchestrates the full defense lifecycle with learning capability.
    """

    def __init__(self, name: str = "BlueAgent-1"):
        self.name = name
        self.agent_logger = AgentLogger(name, "blue_team")
        self.anomaly_detector = AnomalyDetector()
        self.signature_detector = SignatureDetector()
        self.log_parser = LogParser()
        self.traffic_monitor = TrafficMonitor()
        self.response_engine = ResponseEngine()
        self.event_bus = get_event_bus()

        # Subscribe to Red Team events
        self.event_bus.subscribe(EventType.SCAN_STARTED, self._on_scan_detected)
        self.event_bus.subscribe(EventType.EXPLOIT_ATTEMPTED, self._on_exploit_detected)
        self.event_bus.subscribe(EventType.SCAN_COMPLETED, self._on_scan_completed)

    def monitor_and_defend(self, round_id=None) -> dict:
        """
        Run a full defense cycle.

        Returns dict with summary of detections and responses.
        """
        self.agent_logger.action("defense_cycle_start")
        results = {
            "alerts_generated": 0,
            "anomalies_detected": 0,
            "signatures_matched": 0,
            "actions_taken": 0,
            "blocked_ips": [],
        }

        try:
            # Phase 1: Process recent traffic logs
            recent_traffic = TrafficLog.objects.filter(
                is_anomalous=False
            ).order_by("-timestamp")[:200]

            for traffic in recent_traffic:
                detection = self._analyze_traffic(traffic, round_id)
                if detection:
                    results["alerts_generated"] += 1
                    if detection.get("source") == "anomaly":
                        results["anomalies_detected"] += 1
                    else:
                        results["signatures_matched"] += 1

            # Phase 2: Check for behavioral patterns
            behavioral_alerts = self._check_behavioral_patterns(round_id)
            results["alerts_generated"] += len(behavioral_alerts)

            # Phase 3: Respond to new alerts
            new_alerts = Alert.objects.filter(status=Alert.Status.NEW).order_by("-severity")
            for alert in new_alerts:
                actions = self.response_engine.respond(alert, round_id)
                results["actions_taken"] += len(actions)

                alert.status = Alert.Status.CONFIRMED
                alert.save()

                for action in actions:
                    if action.action_type == DefenseAction.ActionType.BLOCK_IP and action.target_ip:
                        results["blocked_ips"].append(action.target_ip)

            self.agent_logger.result(
                "defense_cycle",
                True,
                f"{results['alerts_generated']} alerts, {results['actions_taken']} actions",
            )

        except Exception as e:
            self.agent_logger.error(f"Defense cycle error: {e}", exc_info=True)
            results["error"] = str(e)

        return results

    def _analyze_traffic(self, traffic: TrafficLog, round_id=None) -> Optional[dict]:
        """Analyze a single traffic entry for threats."""
        # Signature-based detection
        sig_matches = self.signature_detector.check(
            traffic.payload_preview or "",
            context={
                "source_ip": traffic.source_ip,
                "dest_port": traffic.destination_port,
                "protocol": traffic.protocol,
            },
        )

        if sig_matches:
            best_match = max(sig_matches, key=lambda m: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(m["severity"], 0))
            alert = Alert.objects.create(
                severity=best_match["severity"],
                source=Alert.Source.SIGNATURE,
                title=best_match["rule_name"],
                description=best_match.get("description", ""),
                source_ip=traffic.source_ip,
                destination_ip=traffic.destination_ip,
                destination_port=traffic.destination_port,
                protocol=traffic.protocol,
                confidence=0.85,
                raw_data={"matches": sig_matches},
                round_id=round_id,
            )
            self.agent_logger.action("signature_alert", target=traffic.source_ip, details=best_match["rule_name"])
            return {"source": "signature", "alert_id": str(alert.id)}

        # ML anomaly detection
        traffic_data = {
            "packet_size": traffic.packet_size,
            "dest_port": traffic.destination_port or 0,
            "packets_per_second": 1,
            "unique_dest_ports": 1,
            "connection_count": 1,
            "avg_payload_size": traffic.packet_size,
            "syn_count": 1 if "SYN" in (traffic.flags or "") else 0,
            "rst_count": 1 if "RST" in (traffic.flags or "") else 0,
        }

        anomaly_result = self.anomaly_detector.detect(traffic_data)

        if anomaly_result.get("is_anomalous"):
            traffic.is_anomalous = True
            traffic.anomaly_score = anomaly_result.get("anomaly_score", 0)
            traffic.save()

            alert = Alert.objects.create(
                severity="medium",
                source=Alert.Source.ANOMALY_ML,
                title=f"Anomalous traffic from {traffic.source_ip}",
                description=anomaly_result.get("reason", "Statistical anomaly"),
                source_ip=traffic.source_ip,
                destination_ip=traffic.destination_ip,
                destination_port=traffic.destination_port,
                confidence=anomaly_result.get("confidence", 0.5),
                raw_data=anomaly_result,
                round_id=round_id,
            )
            self.agent_logger.action("anomaly_alert", target=traffic.source_ip, details=anomaly_result.get("reason", ""))
            return {"source": "anomaly", "alert_id": str(alert.id)}

        return None

    def _check_behavioral_patterns(self, round_id=None) -> list:
        """Check for behavioral patterns like port scanning and brute force."""
        alerts = []
        stats = self.traffic_monitor.get_all_stats()

        for ip, ip_stats in stats.items():
            # Port scan detection
            scan_result = self.signature_detector.detect_port_scan(
                ip, list(range(ip_stats.get("unique_ports", 0))),
            )
            if scan_result:
                alert = Alert.objects.create(
                    severity=scan_result["severity"],
                    source=Alert.Source.TRAFFIC_MONITOR,
                    title=scan_result["rule_name"],
                    description=scan_result["description"],
                    source_ip=ip,
                    confidence=0.8,
                    raw_data=scan_result,
                    round_id=round_id,
                )
                alerts.append(alert)

        return alerts

    def _on_scan_detected(self, event: Event):
        """React to Red Team scan events."""
        target = event.data.get("target", "")
        self.agent_logger.info(f"Detected scan against {target}")

        Alert.objects.create(
            severity="medium",
            source=Alert.Source.TRAFFIC_MONITOR,
            title=f"Scan detected targeting {target}",
            description=f"Scan type: {event.data.get('type', 'unknown')}",
            source_ip=event.data.get("source", ""),
            destination_ip=target,
            confidence=0.9,
            raw_data=event.data,
        )

    def _on_exploit_detected(self, event: Event):
        """React to Red Team exploit events."""
        target = event.data.get("target", "")
        self.agent_logger.warning(f"Exploit attempt detected: {target}")

        alert = Alert.objects.create(
            severity="critical",
            source=Alert.Source.IDS,
            title=f"Exploit attempt against {target}",
            description=f"Type: {event.data.get('type', 'unknown')}, Module: {event.data.get('module', 'unknown')}",
            destination_ip=target.split(":")[0] if ":" in target else target,
            destination_port=int(target.split(":")[1]) if ":" in target else None,
            confidence=0.95,
            raw_data=event.data,
        )

        # Auto-respond to exploits
        self.response_engine.respond(alert)

    def _on_scan_completed(self, event: Event):
        """React when a scan completes."""
        self.agent_logger.info(f"Scan completed: {event.data}")

    def adapt(self, round_id=None):
        """
        Adapt defenses based on recent attack patterns.
        - Retrain anomaly model
        - Generate new detection rules
        - Adjust response thresholds
        """
        self.agent_logger.action("adaptation", details="Retraining and adapting defenses")

        # Retrain anomaly model
        retrained = self.anomaly_detector.retrain(include_recent_alerts=True)

        # Learn new signatures from confirmed attacks
        confirmed_alerts = Alert.objects.filter(status=Alert.Status.CONFIRMED).order_by("-created_at")[:20]
        new_rules = 0
        for alert in confirmed_alerts:
            if alert.raw_data and "matched_text" in str(alert.raw_data):
                # Create signature from matched patterns
                pass  # Future: auto-generate rules from attack patterns

        # Log adaptation decision
        AIDecision.objects.create(
            agent_type="blue",
            agent_name=self.name,
            decision="Adapted defenses based on recent attacks",
            reasoning=f"Retrained model: {retrained}, New rules: {new_rules}",
            confidence=0.7,
            round_id=round_id,
        )

        self.event_bus.publish(Event(
            event_type=EventType.DEFENSE_ADAPTED,
            source="blue_team",
            data={"retrained": retrained, "new_rules": new_rules},
        ))

        self.agent_logger.result("adaptation", True, f"Model retrained={retrained}")

    def get_status(self) -> dict:
        """Get Blue Team agent status."""
        return {
            "agent": self.name,
            "response_engine": self.response_engine.get_status(),
            "stats": {
                "total_alerts": Alert.objects.count(),
                "new_alerts": Alert.objects.filter(status=Alert.Status.NEW).count(),
                "critical_alerts": Alert.objects.filter(severity="critical").count(),
                "total_actions": DefenseAction.objects.count(),
                "active_blocks": DefenseAction.objects.filter(
                    action_type=DefenseAction.ActionType.BLOCK_IP,
                    status=DefenseAction.Status.ACTIVE,
                ).count(),
            },
        }
