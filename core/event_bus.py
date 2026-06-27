"""
Event Bus - Pub/Sub for Inter-Module Communication
====================================================
Decoupled event system allowing Red Team, Blue Team, and Simulation
to communicate without direct dependencies.
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class EventType(Enum):
    """All event types in the system."""

    # Red Team events
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    VULNERABILITY_FOUND = "vulnerability_found"
    EXPLOIT_ATTEMPTED = "exploit_attempted"
    EXPLOIT_SUCCEEDED = "exploit_succeeded"
    EXPLOIT_FAILED = "exploit_failed"
    ATTACK_PLAN_CREATED = "attack_plan_created"

    # Blue Team events
    INTRUSION_DETECTED = "intrusion_detected"
    ANOMALY_DETECTED = "anomaly_detected"
    ALERT_RAISED = "alert_raised"
    IP_BLOCKED = "ip_blocked"
    HONEYPOT_DEPLOYED = "honeypot_deployed"
    DEFENSE_ADAPTED = "defense_adapted"
    RESPONSE_TRIGGERED = "response_triggered"

    # Red Team v2 events
    LATERAL_MOVEMENT = "lateral_movement"

    # Simulation events
    ROUND_STARTED = "round_started"
    ROUND_ENDED = "round_ended"
    SIMULATION_STARTED = "simulation_started"
    SIMULATION_ENDED = "simulation_ended"
    METRICS_UPDATED = "metrics_updated"

    # System events
    SYSTEM_ERROR = "system_error"
    SAFETY_VIOLATION = "safety_violation"
    KILL_SWITCH_ACTIVATED = "kill_switch_activated"


@dataclass
class Event:
    """An event that can be published and subscribed to."""

    event_type: EventType
    data: dict = field(default_factory=dict)
    source: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_id: Optional[str] = None

    def __post_init__(self):
        if self.event_id is None:
            import uuid
            self.event_id = str(uuid.uuid4())

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
        }


class EventBus:
    """
    Thread-safe publish/subscribe event bus.

    Usage:
        bus = EventBus()
        bus.subscribe(EventType.SCAN_COMPLETED, my_handler)
        bus.publish(Event(EventType.SCAN_COMPLETED, data={"target": "10.0.0.1"}))
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._subscribers = {}
                cls._instance._history = []
                cls._instance._max_history = 1000
            return cls._instance

    def subscribe(self, event_type: EventType, callback: Callable[[Event], Any]) -> None:
        """Register a callback for an event type."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)
        logger.debug(f"Subscribed {callback.__name__} to {event_type.value}")

    def unsubscribe(self, event_type: EventType, callback: Callable) -> None:
        """Remove a callback for an event type."""
        if event_type in self._subscribers:
            self._subscribers[event_type] = [
                cb for cb in self._subscribers[event_type] if cb != callback
            ]

    def publish(self, event: Event) -> None:
        """
        Publish an event to all subscribers.
        Callbacks are executed synchronously in the order they were registered.
        """
        logger.info(f"Event published: {event.event_type.value} from {event.source}")

        # Store in history
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        callbacks = self._subscribers.get(event.event_type, [])
        for callback in callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(
                    f"Error in event handler {callback.__name__} for "
                    f"{event.event_type.value}: {e}",
                    exc_info=True,
                )

    def get_history(
        self, event_type: Optional[EventType] = None, limit: int = 100
    ) -> list:
        """Get recent event history, optionally filtered by type."""
        events = self._history
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]

    def clear(self) -> None:
        """Clear all subscribers and history (for testing)."""
        self._subscribers.clear()
        self._history.clear()


# Singleton accessor
def get_event_bus() -> EventBus:
    """Get the global EventBus instance."""
    return EventBus()
