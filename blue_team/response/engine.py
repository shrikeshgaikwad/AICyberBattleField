"""
Response Engine - Automated Defense Actions
=============================================
Selects and executes defensive responses based on threat severity.
"""

import logging
import subprocess
import time
from typing import Optional

from django.utils import timezone

from blue_team.models import Alert, DefenseAction
from core.event_bus import Event, EventType, get_event_bus
from core.models import AgentAction

logger = logging.getLogger("blue_team.response")


class ResponseEngine:
    """
    Automated response engine that selects and executes
    defensive actions based on threat assessment.

    Response levels:
    1. ALERT - Notify administrators
    2. RATE_LIMIT - Throttle suspicious traffic
    3. BLOCK - Block source IP
    4. ISOLATE - Isolate affected host
    5. HONEYPOT - Redirect to honeypot
    """

    # Severity -> default response mapping
    RESPONSE_MAP = {
        "critical": [DefenseAction.ActionType.BLOCK_IP, DefenseAction.ActionType.ALERT_ADMIN],
        "high": [DefenseAction.ActionType.BLOCK_IP, DefenseAction.ActionType.ALERT_ADMIN],
        "medium": [DefenseAction.ActionType.RATE_LIMIT, DefenseAction.ActionType.ALERT_ADMIN],
        "low": [DefenseAction.ActionType.ALERT_ADMIN],
        "info": [DefenseAction.ActionType.ALERT_ADMIN],
    }

    def __init__(self):
        self.event_bus = get_event_bus()
        self._blocked_ips = set()

    def respond(self, alert: Alert, round_id=None) -> list:
        """
        Generate and execute appropriate responses for an alert.

        Args:
            alert: The Alert to respond to.
            round_id: Simulation round ID.

        Returns:
            List of DefenseAction instances.
        """
        actions = []
        response_types = self.RESPONSE_MAP.get(alert.severity, [DefenseAction.ActionType.ALERT_ADMIN])

        for action_type in response_types:
            try:
                action = self._execute_response(alert, action_type, round_id)
                actions.append(action)
            except Exception as e:
                logger.error(f"Failed to execute {action_type}: {e}", exc_info=True)

        return actions

    def _execute_response(self, alert: Alert, action_type: str, round_id=None) -> DefenseAction:
        """Execute a single defense action."""
        action = DefenseAction.objects.create(
            alert=alert,
            action_type=action_type,
            status=DefenseAction.Status.PENDING,
            target_ip=alert.source_ip,
            confidence=alert.confidence,
            reasoning=f"Auto-response to {alert.severity} alert: {alert.title}",
            round_id=round_id,
        )

        start_time = time.time()

        try:
            if action_type == DefenseAction.ActionType.BLOCK_IP:
                result = self._block_ip(alert.source_ip)
            elif action_type == DefenseAction.ActionType.RATE_LIMIT:
                result = self._rate_limit(alert.source_ip)
            elif action_type == DefenseAction.ActionType.HONEYPOT:
                result = self._deploy_honeypot(alert.source_ip, alert.destination_port)
            elif action_type == DefenseAction.ActionType.ISOLATE:
                result = self._isolate_host(alert.destination_ip)
            elif action_type == DefenseAction.ActionType.ALERT_ADMIN:
                result = self._alert_admin(alert)
            elif action_type == DefenseAction.ActionType.UPDATE_RULES:
                result = self._update_rules(alert)
            else:
                result = {"success": True, "message": f"Action logged: {action_type}"}

            action.result = result.get("message", "")
            action.status = DefenseAction.Status.ACTIVE if result.get("success") else DefenseAction.Status.FAILED
            action.duration_seconds = time.time() - start_time
            action.save()

            # Log the action
            AgentAction.objects.create(
                agent_type=AgentAction.AgentType.BLUE,
                agent_name="response_engine",
                action_name=action_type,
                target=alert.source_ip or "",
                success=result.get("success", False),
                result=result.get("message", ""),
                round_id=round_id,
            )

            # Publish event
            self.event_bus.publish(Event(
                event_type=EventType.RESPONSE_TRIGGERED if result.get("success") else EventType.SYSTEM_ERROR,
                source="blue_team.response",
                data={
                    "action_type": action_type,
                    "target_ip": alert.source_ip,
                    "alert_id": str(alert.id),
                    "success": result.get("success", False),
                },
            ))

        except Exception as e:
            action.status = DefenseAction.Status.FAILED
            action.result = str(e)
            action.save()
            logger.error(f"Response action failed: {e}", exc_info=True)

        return action

    def _block_ip(self, ip: str) -> dict:
        """Block an IP address (simulation-safe)."""
        if not ip:
            return {"success": False, "message": "No IP to block"}

        self._blocked_ips.add(ip)
        logger.info(f"BLOCKED IP: {ip}")

        # In a real environment, this would add iptables/firewall rules
        # For simulation, we just track it
        return {"success": True, "message": f"IP {ip} blocked (simulation mode)"}

    def _rate_limit(self, ip: str) -> dict:
        """Apply rate limiting to an IP."""
        if not ip:
            return {"success": False, "message": "No IP to rate limit"}

        logger.info(f"RATE LIMITED: {ip}")
        return {"success": True, "message": f"Rate limiting applied to {ip}"}

    def _deploy_honeypot(self, source_ip: str, port: int = None) -> dict:
        """Deploy a honeypot to deceive the attacker."""
        logger.info(f"HONEYPOT deployed for {source_ip} on port {port}")

        self.event_bus.publish(Event(
            event_type=EventType.HONEYPOT_DEPLOYED,
            source="blue_team.response",
            data={"source_ip": source_ip, "port": port},
        ))

        return {"success": True, "message": f"Honeypot deployed for {source_ip} (port {port})"}

    def _isolate_host(self, host_ip: str) -> dict:
        """Isolate a compromised host."""
        if not host_ip:
            return {"success": False, "message": "No host IP to isolate"}

        logger.info(f"HOST ISOLATED: {host_ip}")
        return {"success": True, "message": f"Host {host_ip} isolated (simulation mode)"}

    def _alert_admin(self, alert: Alert) -> dict:
        """Send alert notification to administrators."""
        logger.warning(
            f"ADMIN ALERT: [{alert.severity.upper()}] {alert.title} "
            f"from {alert.source_ip} -> {alert.destination_ip}:{alert.destination_port}"
        )
        return {"success": True, "message": f"Admin alerted about: {alert.title}"}

    def _update_rules(self, alert: Alert) -> dict:
        """Update detection rules based on the alert."""
        logger.info(f"Detection rules updated based on alert: {alert.title}")
        return {"success": True, "message": "Detection rules updated"}

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        return ip in self._blocked_ips

    def unblock_ip(self, ip: str) -> bool:
        """Unblock a previously blocked IP."""
        if ip in self._blocked_ips:
            self._blocked_ips.discard(ip)
            logger.info(f"UNBLOCKED IP: {ip}")
            return True
        return False

    def get_status(self) -> dict:
        """Get response engine status."""
        return {
            "blocked_ips": list(self._blocked_ips),
            "total_blocked": len(self._blocked_ips),
            "total_actions": DefenseAction.objects.count(),
            "active_actions": DefenseAction.objects.filter(status=DefenseAction.Status.ACTIVE).count(),
        }
