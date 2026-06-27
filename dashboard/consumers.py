"""
Dashboard WebSocket Consumer - Real-Time Battle Updates
=========================================================
Pushes live simulation events, commentary, and metrics to the dashboard
via Django Channels WebSocket.
"""

import json
import logging

try:
    from channels.generic.websocket import AsyncWebSocketConsumer
    from channels.db import database_sync_to_async
    HAS_ASYNC_WEBSOCKET = True
except ImportError:
    # Fallback: define a dummy base so the module can still be imported
    from channels.generic.websocket import WebsocketConsumer as _BaseConsumer
    AsyncWebSocketConsumer = _BaseConsumer
    HAS_ASYNC_WEBSOCKET = False

    def database_sync_to_async(func):
        return func

logger = logging.getLogger("dashboard.ws")


class BattlefieldConsumer(AsyncWebSocketConsumer):
    """
    WebSocket consumer for real-time battlefield updates.
    Clients join the 'battlefield' group to receive live events.
    """

    async def connect(self):
        self.group_name = "battlefield"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        logger.info(f"WebSocket connected: {self.channel_name}")

        # Send initial state
        initial_data = await self.get_initial_state()
        await self.send(text_data=json.dumps({
            "type": "initial_state",
            "data": initial_data,
        }))

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)
        logger.info(f"WebSocket disconnected: {self.channel_name}")

    async def receive(self, text_data):
        """Handle messages from the client (e.g., filter requests)."""
        try:
            data = json.loads(text_data)
            msg_type = data.get("type", "")

            if msg_type == "get_stats":
                stats = await self.get_live_stats()
                await self.send(text_data=json.dumps({
                    "type": "stats_update",
                    "data": stats,
                }))
            elif msg_type == "get_commentary":
                commentary = await self.get_recent_commentary()
                await self.send(text_data=json.dumps({
                    "type": "commentary",
                    "data": commentary,
                }))
            elif msg_type == "get_topology":
                topology = await self.get_topology_data()
                await self.send(text_data=json.dumps({
                    "type": "topology",
                    "data": topology,
                }))

        except json.JSONDecodeError:
            pass

    # ─── Group message handlers (pushed from server) ──────────────

    async def battle_event(self, event):
        """Push a battle event to connected clients."""
        await self.send(text_data=json.dumps({
            "type": "battle_event",
            "data": event.get("data", {}),
        }))

    async def round_update(self, event):
        """Push round score updates."""
        await self.send(text_data=json.dumps({
            "type": "round_update",
            "data": event.get("data", {}),
        }))

    async def commentary_update(self, event):
        """Push new commentary."""
        await self.send(text_data=json.dumps({
            "type": "commentary",
            "data": event.get("data", {}),
        }))

    async def stats_update(self, event):
        """Push updated stats."""
        await self.send(text_data=json.dumps({
            "type": "stats_update",
            "data": event.get("data", {}),
        }))

    async def topology_update(self, event):
        """Push topology state change (host compromised, etc.)."""
        await self.send(text_data=json.dumps({
            "type": "topology_update",
            "data": event.get("data", {}),
        }))

    # ─── Database helpers ────────────────────────────────────────

    @database_sync_to_async
    def get_initial_state(self):
        from red_team.models import ScanResult, ExploitAttempt, Vulnerability
        from blue_team.models import Alert, DefenseAction
        from simulation.models import SimulationConfig, SimulationRound

        return {
            "red_team": {
                "scans": ScanResult.objects.count(),
                "vulns": Vulnerability.objects.count(),
                "exploits_success": ExploitAttempt.objects.filter(status="success").count(),
                "exploits_total": ExploitAttempt.objects.count(),
            },
            "blue_team": {
                "alerts": Alert.objects.count(),
                "blocks": DefenseAction.objects.filter(action_type="block_ip", status="active").count(),
                "detections": Alert.objects.filter(source="anomaly_ml").count(),
            },
            "simulation": {
                "total": SimulationConfig.objects.count(),
                "running": SimulationConfig.objects.filter(status="running").count(),
                "total_rounds": SimulationRound.objects.count(),
            },
        }

    @database_sync_to_async
    def get_live_stats(self):
        from red_team.models import ScanResult, ExploitAttempt, Vulnerability
        from blue_team.models import Alert, DefenseAction, TrafficLog
        from simulation.models import SimulationRound

        rounds = SimulationRound.objects.filter(status="completed").order_by("-id")[:20]
        return {
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
        }

    @database_sync_to_async
    def get_recent_commentary(self):
        from core.models import SystemEvent
        events = SystemEvent.objects.filter(
            source="battle_commentary"
        ).order_by("-created_at")[:20]
        return [
            {
                "text": e.message,
                "event_type": e.event_type,
                "timestamp": e.created_at.isoformat(),
            }
            for e in events
        ]

    @database_sync_to_async
    def get_topology_data(self):
        """Get current topology state (if available in cache)."""
        return {"message": "Use simulation API to get topology state"}


def push_battle_event(event_type: str, data: dict):
    """
    Push a battle event to all connected WebSocket clients.
    Call this from synchronous code (e.g., event bus handlers).
    """
    try:
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync

        channel_layer = get_channel_layer()
        if channel_layer:
            async_to_sync(channel_layer.group_send)(
                "battlefield",
                {
                    "type": "battle_event",
                    "data": {"event_type": event_type, **data},
                },
            )
    except Exception:
        pass  # WebSocket push is best-effort
