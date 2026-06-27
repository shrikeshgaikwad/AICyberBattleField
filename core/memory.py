"""
Agent Memory Store - Episodic & Strategic Memory
==================================================
Provides persistent memory for AI agents to learn across simulations.
Stores attack/defense episodes as searchable records with outcomes.
"""

import hashlib
import json
import logging
from collections import defaultdict
from typing import Optional

from django.db import models
from django.utils import timezone

logger = logging.getLogger(__name__)


class MemoryEntry(models.Model):
    """A single memory episode from an agent's experience."""

    class MemoryType(models.TextChoices):
        ATTACK_SUCCESS = "attack_success", "Successful Attack"
        ATTACK_FAILURE = "attack_failure", "Failed Attack"
        DEFENSE_SUCCESS = "defense_success", "Successful Defense"
        DEFENSE_FAILURE = "defense_failure", "Failed Defense"
        EVASION = "evasion", "Evasion Tactic"
        DETECTION = "detection", "Detection Pattern"
        STRATEGY = "strategy", "Strategic Insight"
        ADAPTATION = "adaptation", "Adaptation Record"

    import uuid
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent_name = models.CharField(max_length=100, db_index=True)
    agent_type = models.CharField(max_length=10, choices=[("red", "Red"), ("blue", "Blue")])
    memory_type = models.CharField(max_length=20, choices=MemoryType.choices)

    # Context: what was happening
    target_ip = models.GenericIPAddressField(null=True, blank=True)
    target_port = models.IntegerField(null=True, blank=True)
    target_service = models.CharField(max_length=200, blank=True, default="")
    action_taken = models.CharField(max_length=200)
    action_parameters = models.JSONField(default=dict, blank=True)

    # Outcome
    success = models.BooleanField(default=False)
    outcome_details = models.TextField(blank=True, default="")
    reward = models.FloatField(default=0.0)

    # Learned insight
    lesson = models.TextField(blank=True, default="",
                              help_text="What the agent learned from this experience")
    tags = models.JSONField(default=list, blank=True,
                            help_text="Searchable tags: ['port_scan', 'ssh', 'evasion']")

    # Context fingerprint for similarity search
    context_hash = models.CharField(max_length=64, blank=True, default="", db_index=True)

    # Strength: how relevant this memory still is (decays over time)
    strength = models.FloatField(default=1.0,
                                 help_text="Memory strength, decays over time (0.0-1.0)")

    round_id = models.UUIDField(null=True, blank=True)
    simulation_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        app_label = "core"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["agent_name", "memory_type"]),
            models.Index(fields=["agent_type", "success"]),
            models.Index(fields=["target_service", "action_taken"]),
        ]

    def __str__(self):
        return f"[{self.agent_type}] {self.memory_type}: {self.action_taken} -> {'✓' if self.success else '✗'}"


class AgentMemory:
    """
    Memory store for an AI agent. Provides recall, storage, and
    pattern recognition across simulations.

    Usage:
        memory = AgentMemory("RedAgent-1", "red")
        memory.remember(
            memory_type="attack_success",
            action_taken="exploit_metasploit",
            target_service="ssh",
            target_port=22,
            success=True,
            outcome="Root shell obtained via CVE-2024-1234",
            lesson="SSH on port 22 with OpenSSH 7.4 is exploitable via CVE-2024-1234",
            reward=25.0,
        )

        # Later...
        past = memory.recall_similar(target_service="ssh", target_port=22)
        # Returns past experiences with SSH on port 22
    """

    def __init__(self, agent_name: str, agent_type: str):
        self.agent_name = agent_name
        self.agent_type = agent_type
        self._cache = {}

    def remember(
        self,
        memory_type: str,
        action_taken: str,
        target_ip: str = None,
        target_port: int = None,
        target_service: str = "",
        success: bool = False,
        outcome: str = "",
        lesson: str = "",
        reward: float = 0.0,
        tags: list = None,
        action_parameters: dict = None,
        round_id=None,
        simulation_id=None,
    ) -> MemoryEntry:
        """Store a new memory from an experience."""
        context_hash = self._compute_context_hash(
            target_service=target_service,
            target_port=target_port,
            action_taken=action_taken,
        )

        entry = MemoryEntry.objects.create(
            agent_name=self.agent_name,
            agent_type=self.agent_type,
            memory_type=memory_type,
            target_ip=target_ip,
            target_port=target_port,
            target_service=target_service,
            action_taken=action_taken,
            action_parameters=action_parameters or {},
            success=success,
            outcome_details=outcome,
            reward=reward,
            lesson=lesson,
            tags=tags or [],
            context_hash=context_hash,
            round_id=round_id,
            simulation_id=simulation_id,
        )

        logger.info(
            f"Memory stored: [{self.agent_type}] {action_taken} -> "
            f"{'success' if success else 'failure'} (reward={reward:.1f})"
        )
        return entry

    def recall_similar(
        self,
        target_service: str = None,
        target_port: int = None,
        action_taken: str = None,
        memory_type: str = None,
        success_only: bool = False,
        limit: int = 10,
    ) -> list:
        """
        Recall memories similar to the given context.
        Returns most relevant memories sorted by strength and recency.
        """
        qs = MemoryEntry.objects.filter(
            agent_name=self.agent_name,
            strength__gt=0.1,
        )

        if target_service:
            qs = qs.filter(target_service__icontains=target_service)
        if target_port is not None:
            qs = qs.filter(target_port=target_port)
        if action_taken:
            qs = qs.filter(action_taken__icontains=action_taken)
        if memory_type:
            qs = qs.filter(memory_type=memory_type)
        if success_only:
            qs = qs.filter(success=True)

        return list(qs.order_by("-strength", "-created_at")[:limit])

    def recall_by_context(self, target_service: str, target_port: int, action_taken: str, limit: int = 5) -> list:
        """Recall memories with an exact context match."""
        context_hash = self._compute_context_hash(target_service, target_port, action_taken)
        return list(
            MemoryEntry.objects.filter(
                agent_name=self.agent_name,
                context_hash=context_hash,
                strength__gt=0.1,
            ).order_by("-strength", "-created_at")[:limit]
        )

    def recall_for_target(self, target_ip: str, limit: int = 20) -> list:
        """Recall all memories about a specific target."""
        return list(
            MemoryEntry.objects.filter(
                agent_name=self.agent_name,
                target_ip=target_ip,
                strength__gt=0.1,
            ).order_by("-strength", "-created_at")[:limit]
        )

    def get_success_rate(self, action_taken: str, target_service: str = None) -> dict:
        """Get historical success rate for a specific action."""
        qs = MemoryEntry.objects.filter(
            agent_name=self.agent_name,
            action_taken__icontains=action_taken,
        )
        if target_service:
            qs = qs.filter(target_service__icontains=target_service)

        total = qs.count()
        if total == 0:
            return {"total": 0, "successes": 0, "rate": 0.0}

        successes = qs.filter(success=True).count()
        return {
            "total": total,
            "successes": successes,
            "rate": successes / total,
        }

    def get_best_strategy(self, target_service: str, target_port: int = None) -> Optional[dict]:
        """
        Find the most successful strategy for attacking/defending a service.
        Returns the action with highest historical reward.
        """
        qs = MemoryEntry.objects.filter(
            agent_name=self.agent_name,
            target_service__icontains=target_service,
            success=True,
        )
        if target_port:
            qs = qs.filter(target_port=target_port)

        # Group by action, get average reward
        from django.db.models import Avg, Count
        strategies = (
            qs.values("action_taken")
            .annotate(avg_reward=Avg("reward"), count=Count("id"))
            .order_by("-avg_reward")
        )

        if strategies:
            best = strategies[0]
            return {
                "action": best["action_taken"],
                "avg_reward": best["avg_reward"],
                "times_used": best["count"],
            }
        return None

    def build_context_summary(self, target_ip: str = None, limit: int = 10) -> str:
        """
        Build a natural language summary of past experiences for LLM context.
        This can be injected into LLM prompts for better decision-making.
        """
        if target_ip:
            memories = self.recall_for_target(target_ip, limit=limit)
        else:
            memories = list(
                MemoryEntry.objects.filter(
                    agent_name=self.agent_name,
                    strength__gt=0.3,
                ).order_by("-reward", "-created_at")[:limit]
            )

        if not memories:
            return "No prior experience available."

        lines = ["=== AGENT MEMORY (Past Experiences) ==="]
        for mem in memories:
            status = "SUCCESS" if mem.success else "FAILURE"
            lines.append(
                f"- [{status}] {mem.action_taken} on {mem.target_service}:{mem.target_port} "
                f"(reward: {mem.reward:.1f})"
            )
            if mem.lesson:
                lines.append(f"  Lesson: {mem.lesson}")

        # Add strategic insights
        strategies = (
            MemoryEntry.objects.filter(
                agent_name=self.agent_name,
                memory_type=MemoryEntry.MemoryType.STRATEGY,
            )
            .order_by("-created_at")[:3]
        )
        if strategies:
            lines.append("\n=== STRATEGIC INSIGHTS ===")
            for s in strategies:
                lines.append(f"- {s.lesson}")

        return "\n".join(lines)

    def decay_memories(self, decay_factor: float = 0.95):
        """Decay all memory strengths. Call after each simulation."""
        updated = MemoryEntry.objects.filter(
            agent_name=self.agent_name,
            strength__gt=0.05,
        ).update(strength=models.F("strength") * decay_factor)

        # Remove very weak memories
        deleted, _ = MemoryEntry.objects.filter(
            agent_name=self.agent_name,
            strength__lte=0.05,
        ).delete()

        logger.info(f"Memory decay: {updated} decayed, {deleted} pruned for {self.agent_name}")

    def reinforce(self, memory_id, boost: float = 0.2):
        """Reinforce a memory (make it stronger/more accessible)."""
        try:
            mem = MemoryEntry.objects.get(id=memory_id, agent_name=self.agent_name)
            mem.strength = min(1.0, mem.strength + boost)
            mem.save(update_fields=["strength"])
        except MemoryEntry.DoesNotExist:
            pass

    def get_stats(self) -> dict:
        """Get memory statistics for this agent."""
        from django.db.models import Avg, Count, Sum
        qs = MemoryEntry.objects.filter(agent_name=self.agent_name)
        stats = qs.aggregate(
            total=Count("id"),
            avg_reward=Avg("reward"),
            total_reward=Sum("reward"),
            avg_strength=Avg("strength"),
        )
        stats["success_rate"] = (
            qs.filter(success=True).count() / max(stats["total"], 1)
        )
        return stats

    @staticmethod
    def _compute_context_hash(target_service: str = "", target_port: int = None, action_taken: str = "") -> str:
        """Compute a deterministic hash for context-based lookups."""
        context = f"{target_service}:{target_port}:{action_taken}"
        return hashlib.sha256(context.encode()).hexdigest()[:16]
