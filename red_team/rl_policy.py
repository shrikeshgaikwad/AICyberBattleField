"""
RL Policy - Red Team Reinforcement Learning
=============================================
Q-learning based policy that improves attack strategies over time.
Learns which actions work best for different service/port combinations.
"""

import json
import logging
import random
from collections import defaultdict
from pathlib import Path
from typing import Optional

from django.conf import settings

logger = logging.getLogger("red_team.rl")

# Default Q-values for known action-context pairs
DEFAULT_Q = 0.0
LEARNING_RATE = 0.1
DISCOUNT_FACTOR = 0.9
EXPLORATION_RATE = 0.15  # epsilon for epsilon-greedy


class RedTeamPolicy:
    """
    Q-learning policy for Red Team action selection.

    State: (target_service, target_port, defense_level)
    Action: exploit type / technique to use
    Reward: based on exploitation success and evasion

    Persists Q-table to disk for cross-simulation learning.
    """

    ACTIONS = [
        "exploit_metasploit",
        "exploit_sqlmap",
        "bruteforce",
        "fuzz",
        "nmap_scan",
        "vuln_scan",
        "enumerate_service",
        "custom_script",
    ]

    def __init__(self, policy_path: Optional[str] = None):
        self.policy_path = policy_path or str(
            Path(settings.BASE_DIR) / "models" / "red_team_policy.json"
        )
        self.q_table = defaultdict(lambda: defaultdict(float))
        self.action_counts = defaultdict(lambda: defaultdict(int))
        self.epsilon = EXPLORATION_RATE
        self.alpha = LEARNING_RATE
        self.gamma = DISCOUNT_FACTOR
        self._load_policy()

    def _state_key(self, service: str, port: int, defense_level: str = "unknown") -> str:
        """Create a state key from context."""
        return f"{service}:{port}:{defense_level}"

    def select_action(self, service: str, port: int, defense_level: str = "unknown",
                      available_actions: list = None) -> str:
        """
        Select the best action for the current state using epsilon-greedy.

        Args:
            service: Target service name (e.g., 'http', 'ssh')
            port: Target port number
            defense_level: Observed defense level ('low', 'medium', 'high', 'unknown')
            available_actions: Subset of actions available. If None, uses all.

        Returns:
            Selected action string.
        """
        state = self._state_key(service, port, defense_level)
        actions = available_actions or self.ACTIONS

        # Epsilon-greedy exploration
        if random.random() < self.epsilon:
            action = random.choice(actions)
            logger.debug(f"RL: Exploring with random action: {action}")
            return action

        # Exploit: choose highest Q-value action
        q_values = {a: self.q_table[state][a] for a in actions}
        best_action = max(q_values, key=q_values.get)

        logger.debug(
            f"RL: State={state}, Best={best_action} "
            f"(Q={q_values[best_action]:.3f}), "
            f"Top3={sorted(q_values.items(), key=lambda x: -x[1])[:3]}"
        )
        return best_action

    def update(self, service: str, port: int, action: str, reward: float,
               next_service: str = None, next_port: int = None,
               defense_level: str = "unknown"):
        """
        Update Q-value based on action outcome.

        Q(s,a) = Q(s,a) + α * [reward + γ * max(Q(s',a')) - Q(s,a)]
        """
        state = self._state_key(service, port, defense_level)
        next_state = self._state_key(
            next_service or service,
            next_port or port,
            defense_level,
        )

        # Current Q-value
        current_q = self.q_table[state][action]

        # Best future Q-value
        next_q_values = self.q_table[next_state]
        max_next_q = max(next_q_values.values()) if next_q_values else 0.0

        # Q-learning update
        new_q = current_q + self.alpha * (reward + self.gamma * max_next_q - current_q)
        self.q_table[state][action] = new_q

        # Track action counts
        self.action_counts[state][action] += 1

        logger.info(
            f"RL Update: state={state}, action={action}, "
            f"reward={reward:.1f}, Q: {current_q:.3f} -> {new_q:.3f}"
        )

    def get_action_ranking(self, service: str, port: int,
                           defense_level: str = "unknown") -> list:
        """Get all actions ranked by Q-value for a given state."""
        state = self._state_key(service, port, defense_level)
        q_values = {a: self.q_table[state].get(a, DEFAULT_Q) for a in self.ACTIONS}
        return sorted(q_values.items(), key=lambda x: -x[1])

    def compute_reward(self, result: dict) -> float:
        """
        Compute reward from an action result.

        Reward structure:
        - Successful exploit: +25
        - Vulnerability found: +10
        - Successful scan: +5
        - Evasion (exploit succeeded despite defenses): +15
        - Failed exploit: -5
        - Blocked by defense: -10
        - Safety violation: -50
        """
        reward = 0.0

        if result.get("success"):
            reward += 25.0
            if result.get("session_obtained"):
                reward += 20.0
            if result.get("access_level") in ("root", "system", "admin"):
                reward += 15.0
            if result.get("evaded_detection"):
                reward += 15.0
        else:
            reward -= 5.0
            if result.get("blocked"):
                reward -= 10.0
            if result.get("detected"):
                reward -= 5.0

        if result.get("vulns_found", 0) > 0:
            reward += result["vulns_found"] * 10.0

        if result.get("safety_violation"):
            reward -= 50.0

        return reward

    def decay_exploration(self, min_epsilon: float = 0.05):
        """Decay exploration rate over time (encourage exploitation of learned knowledge)."""
        self.epsilon = max(min_epsilon, self.epsilon * 0.99)

    def save_policy(self):
        """Save Q-table and metadata to disk."""
        data = {
            "q_table": {k: dict(v) for k, v in self.q_table.items()},
            "action_counts": {k: dict(v) for k, v in self.action_counts.items()},
            "epsilon": self.epsilon,
        }
        Path(self.policy_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.policy_path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Red Team RL policy saved ({len(self.q_table)} states)")

    def _load_policy(self):
        """Load Q-table from disk if available."""
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
                logger.info(f"Red Team RL policy loaded ({len(self.q_table)} states)")
        except Exception as e:
            logger.warning(f"Could not load RL policy: {e}")

    def get_stats(self) -> dict:
        """Get policy statistics."""
        total_states = len(self.q_table)
        total_updates = sum(
            sum(counts.values())
            for counts in self.action_counts.values()
        )
        return {
            "total_states": total_states,
            "total_updates": total_updates,
            "epsilon": self.epsilon,
            "top_strategies": self._get_top_strategies(5),
        }

    def _get_top_strategies(self, n: int = 5) -> list:
        """Get top N state-action pairs by Q-value."""
        all_pairs = []
        for state, actions in self.q_table.items():
            for action, q_val in actions.items():
                all_pairs.append({
                    "state": state,
                    "action": action,
                    "q_value": q_val,
                    "times_used": self.action_counts[state].get(action, 0),
                })
        return sorted(all_pairs, key=lambda x: -x["q_value"])[:n]
