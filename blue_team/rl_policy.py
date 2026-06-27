"""
RL Policy - Blue Team Reinforcement Learning
==============================================
Q-learning policy for defensive action selection.
Learns optimal response strategies based on threat patterns and outcomes.
"""

import json
import logging
import random
from collections import defaultdict
from pathlib import Path
from typing import Optional

from django.conf import settings

logger = logging.getLogger("blue_team.rl")

DEFAULT_Q = 0.0
LEARNING_RATE = 0.1
DISCOUNT_FACTOR = 0.9
EXPLORATION_RATE = 0.15


class BlueTeamPolicy:
    """
    Q-learning policy for Blue Team response selection.

    State: (alert_severity, attack_type, source_behavior)
    Action: defense response type
    Reward: based on detection accuracy, response effectiveness
    """

    ACTIONS = [
        "block_ip",
        "rate_limit",
        "honeypot",
        "isolate",
        "patch",
        "alert_admin",
        "update_rules",
        "quarantine",
        "ignore",  # intentional non-action for low-confidence alerts
    ]

    def __init__(self, policy_path: Optional[str] = None):
        self.policy_path = policy_path or str(
            Path(settings.BASE_DIR) / "models" / "blue_team_policy.json"
        )
        self.q_table = defaultdict(lambda: defaultdict(float))
        self.action_counts = defaultdict(lambda: defaultdict(int))
        self.epsilon = EXPLORATION_RATE
        self.alpha = LEARNING_RATE
        self.gamma = DISCOUNT_FACTOR
        self._load_policy()

    def _state_key(self, severity: str, attack_type: str,
                   confidence: float = 0.5) -> str:
        """Create state key from alert context."""
        conf_level = "high" if confidence > 0.7 else "medium" if confidence > 0.4 else "low"
        return f"{severity}:{attack_type}:{conf_level}"

    def select_action(self, severity: str, attack_type: str,
                      confidence: float = 0.5,
                      available_actions: list = None) -> str:
        """
        Select best defensive action using epsilon-greedy.

        Args:
            severity: Alert severity level
            attack_type: Type of detected attack
            confidence: Detection confidence (0.0-1.0)
            available_actions: Subset of available actions

        Returns:
            Selected defensive action string.
        """
        state = self._state_key(severity, attack_type, confidence)
        actions = available_actions or self.ACTIONS

        # Epsilon-greedy
        if random.random() < self.epsilon:
            action = random.choice(actions)
            logger.debug(f"Blue RL: Exploring with {action}")
            return action

        q_values = {a: self.q_table[state][a] for a in actions}
        best_action = max(q_values, key=q_values.get)

        logger.debug(
            f"Blue RL: State={state}, Best={best_action} "
            f"(Q={q_values[best_action]:.3f})"
        )
        return best_action

    def update(self, severity: str, attack_type: str, action: str,
               reward: float, confidence: float = 0.5):
        """
        Update Q-value from defense outcome.

        Q(s,a) = Q(s,a) + α * [reward + γ * max(Q(s',a')) - Q(s,a)]
        """
        state = self._state_key(severity, attack_type, confidence)
        current_q = self.q_table[state][action]

        # For terminal states (defense actions are often terminal), we skip next-state
        new_q = current_q + self.alpha * (reward - current_q)
        self.q_table[state][action] = new_q
        self.action_counts[state][action] += 1

        logger.info(
            f"Blue RL Update: state={state}, action={action}, "
            f"reward={reward:.1f}, Q: {current_q:.3f} -> {new_q:.3f}"
        )

    def compute_reward(self, result: dict) -> float:
        """
        Compute reward for a defensive action.

        Reward structure:
        - Attack blocked successfully: +25
        - Attack detected early: +15
        - Correct alert (true positive): +10
        - False positive (blocked legitimate): -20
        - Missed attack (false negative): -30
        - Unnecessary escalation: -5
        - Successful honeypot engagement: +20
        """
        reward = 0.0

        if result.get("attack_blocked"):
            reward += 25.0
        if result.get("early_detection"):
            reward += 15.0
        if result.get("true_positive"):
            reward += 10.0
        if result.get("false_positive"):
            reward -= 20.0
        if result.get("false_negative"):
            reward -= 30.0
        if result.get("honeypot_engaged"):
            reward += 20.0
        if result.get("unnecessary_escalation"):
            reward -= 5.0

        # Bonus for response time
        response_time = result.get("response_time_ms", 0)
        if response_time > 0 and response_time < 1000:
            reward += 5.0  # Fast response bonus

        return reward

    def get_recommended_responses(self, severity: str, attack_type: str,
                                  confidence: float = 0.5, top_n: int = 3) -> list:
        """Get top N recommended responses ranked by Q-value."""
        state = self._state_key(severity, attack_type, confidence)
        q_values = {a: self.q_table[state].get(a, DEFAULT_Q) for a in self.ACTIONS}
        ranked = sorted(q_values.items(), key=lambda x: -x[1])
        return [
            {"action": action, "q_value": q_val, "times_used": self.action_counts[state].get(action, 0)}
            for action, q_val in ranked[:top_n]
        ]

    def decay_exploration(self, min_epsilon: float = 0.05):
        """Decay exploration rate."""
        self.epsilon = max(min_epsilon, self.epsilon * 0.99)

    def save_policy(self):
        """Save policy to disk."""
        data = {
            "q_table": {k: dict(v) for k, v in self.q_table.items()},
            "action_counts": {k: dict(v) for k, v in self.action_counts.items()},
            "epsilon": self.epsilon,
        }
        Path(self.policy_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.policy_path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Blue Team RL policy saved ({len(self.q_table)} states)")

    def _load_policy(self):
        """Load policy from disk."""
        try:
            path = Path(self.policy_path)
            if path.exists():
                with open(path) as f:
                    data = json.load(f)
                for state, actions in data.get("q_table", {}).items():
                    for action, q_val in actions.items():
                        self.q_table[state][action] = q_val
                for state, actions in data.get("action_counts", {}).items():
                    for action, count in actions.items():
                        self.action_counts[state][action] = count
                self.epsilon = data.get("epsilon", EXPLORATION_RATE)
                logger.info(f"Blue Team RL policy loaded ({len(self.q_table)} states)")
        except Exception as e:
            logger.warning(f"Could not load Blue RL policy: {e}")

    def get_stats(self) -> dict:
        """Get policy statistics."""
        total_states = len(self.q_table)
        total_updates = sum(
            sum(counts.values()) for counts in self.action_counts.values()
        )
        return {
            "total_states": total_states,
            "total_updates": total_updates,
            "epsilon": self.epsilon,
        }
