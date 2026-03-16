"""
Safety Module - Scope Validation, Rate Limiting, Kill Switch
=============================================================
Ensures all offensive operations stay within allowed scope.
"""

import ipaddress
import logging
import signal
import threading
from datetime import datetime, timezone
from typing import Optional

from django.conf import settings

from core.event_bus import Event, EventType, get_event_bus

logger = logging.getLogger(__name__)


class SafetyError(Exception):
    """Raised when a safety constraint is violated."""
    pass


class SafetyModule:
    """
    Enforces safety constraints on all operations.

    - IP/CIDR whitelist validation
    - Action rate limiting per round
    - Kill switch for emergency shutdown
    - Action validation and sanitization
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self._kill_switch = False
        self._action_count = 0
        self._round_action_counts = {}
        self._current_round = None
        self._blocked_actions = []

        # Parse allowed CIDRs
        self._allowed_networks = []
        cidrs = getattr(settings, "ALLOWED_TARGET_CIDRS", [])
        for cidr in cidrs:
            try:
                self._allowed_networks.append(ipaddress.ip_network(cidr.strip(), strict=False))
            except ValueError as e:
                logger.error(f"Invalid CIDR in safety config: {cidr} - {e}")

        self._max_actions = getattr(settings, "MAX_ACTIONS_PER_ROUND", 50)

        # Register signal handlers for kill switch
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (OSError, ValueError):
            # Can't set signal handlers in non-main thread
            pass

        logger.info(
            f"Safety module initialized: {len(self._allowed_networks)} allowed networks, "
            f"max {self._max_actions} actions/round"
        )

    def _signal_handler(self, signum, frame):
        """Handle kill signals."""
        logger.critical(f"Kill switch activated via signal {signum}")
        self.activate_kill_switch("Signal received")

    def validate_target(self, target_ip: str) -> bool:
        """
        Check if a target IP is within allowed scope.

        Args:
            target_ip: IP address to validate.

        Returns:
            True if target is allowed, False otherwise.

        Raises:
            SafetyError: If kill switch is active.
        """
        self._check_kill_switch()

        try:
            ip = ipaddress.ip_address(target_ip.strip())
        except ValueError:
            logger.warning(f"Invalid IP address: {target_ip}")
            return False

        for network in self._allowed_networks:
            if ip in network:
                return True

        logger.warning(f"Target {target_ip} is OUTSIDE allowed scope")
        get_event_bus().publish(Event(
            event_type=EventType.SAFETY_VIOLATION,
            source="safety",
            data={"type": "out_of_scope", "target": target_ip},
        ))
        return False

    def validate_action(self, action: dict) -> bool:
        """
        Validate an action before execution.

        Args:
            action: Dict with at least 'type' and optionally 'target', 'command'.

        Returns:
            True if action is allowed.

        Raises:
            SafetyError: If kill switch is active or rate limit exceeded.
        """
        self._check_kill_switch()

        # Check rate limit
        if self._action_count >= self._max_actions:
            logger.warning(f"Rate limit reached: {self._action_count}/{self._max_actions}")
            raise SafetyError(f"Action rate limit exceeded: {self._action_count}/{self._max_actions}")

        # Validate target if present
        target = action.get("target", "")
        if target:
            if not self.validate_target(target):
                raise SafetyError(f"Target {target} is outside allowed scope")

        # Block dangerous commands
        dangerous_patterns = [
            "rm -rf /",
            "format c:",
            ":(){:|:&};:",  # Fork bomb
            "dd if=/dev/zero",
            "> /dev/sda",
        ]
        command = action.get("command", "")
        for pattern in dangerous_patterns:
            if pattern in command.lower():
                logger.critical(f"BLOCKED dangerous command: {command}")
                raise SafetyError(f"Dangerous command blocked: {pattern}")

        self._action_count += 1
        return True

    def reset_round(self, round_id: Optional[str] = None):
        """Reset action counter for a new simulation round."""
        if self._current_round:
            self._round_action_counts[self._current_round] = self._action_count
        self._current_round = round_id
        self._action_count = 0
        logger.info(f"Safety counters reset for round {round_id}")

    def activate_kill_switch(self, reason: str = "Manual activation"):
        """Activate the kill switch - halts all operations."""
        self._kill_switch = True
        logger.critical(f"KILL SWITCH ACTIVATED: {reason}")
        get_event_bus().publish(Event(
            event_type=EventType.KILL_SWITCH_ACTIVATED,
            source="safety",
            data={"reason": reason, "timestamp": datetime.now(timezone.utc).isoformat()},
        ))

    def deactivate_kill_switch(self):
        """Deactivate kill switch (requires explicit call)."""
        self._kill_switch = False
        self._action_count = 0
        logger.warning("Kill switch deactivated")

    def _check_kill_switch(self):
        """Raise if kill switch is active."""
        if self._kill_switch:
            raise SafetyError("Kill switch is active - all operations halted")

    @property
    def is_active(self) -> bool:
        """Whether the kill switch is currently active."""
        return self._kill_switch

    @property
    def actions_remaining(self) -> int:
        """Number of actions remaining in current round."""
        return max(0, self._max_actions - self._action_count)

    def get_status(self) -> dict:
        """Get current safety module status."""
        return {
            "kill_switch_active": self._kill_switch,
            "actions_this_round": self._action_count,
            "max_actions_per_round": self._max_actions,
            "actions_remaining": self.actions_remaining,
            "allowed_networks": [str(n) for n in self._allowed_networks],
            "current_round": self._current_round,
        }


# Singleton accessor
def get_safety_module() -> SafetyModule:
    """Get the global SafetyModule instance."""
    return SafetyModule()
