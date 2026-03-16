"""
Core Models - Shared data models for logging and system events.
"""

import uuid

from django.db import models
from django.utils import timezone


class AgentAction(models.Model):
    """Audit trail of every agent action (red or blue team)."""

    class AgentType(models.TextChoices):
        RED = "red", "Red Team"
        BLUE = "blue", "Blue Team"
        SYSTEM = "system", "System"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent_type = models.CharField(max_length=10, choices=AgentType.choices)
    agent_name = models.CharField(max_length=100)
    action_name = models.CharField(max_length=200)
    target = models.CharField(max_length=200, blank=True, default="")
    parameters = models.JSONField(default=dict, blank=True)
    result = models.TextField(blank=True, default="")
    success = models.BooleanField(null=True)
    error_message = models.TextField(blank=True, default="")
    duration_ms = models.FloatField(null=True, blank=True)
    round_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["agent_type", "created_at"]),
            models.Index(fields=["round_id"]),
        ]

    def __str__(self):
        return f"[{self.agent_type}] {self.agent_name}: {self.action_name}"


class AIDecision(models.Model):
    """Records LLM reasoning, confidence, and outcomes."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent_type = models.CharField(max_length=10, choices=AgentAction.AgentType.choices)
    agent_name = models.CharField(max_length=100)
    decision = models.TextField()
    reasoning = models.TextField(blank=True, default="")
    confidence = models.FloatField(default=0.0)
    context = models.JSONField(default=dict, blank=True)
    outcome = models.TextField(blank=True, default="")
    outcome_success = models.BooleanField(null=True)
    llm_model = models.CharField(max_length=100, blank=True, default="")
    prompt_tokens = models.IntegerField(default=0)
    completion_tokens = models.IntegerField(default=0)
    duration_ms = models.FloatField(null=True, blank=True)
    round_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name_plural = "AI Decisions"

    def __str__(self):
        return f"[{self.agent_type}] {self.decision[:80]}"


class SystemEvent(models.Model):
    """System-wide event log."""

    class Severity(models.TextChoices):
        DEBUG = "debug", "Debug"
        INFO = "info", "Info"
        WARNING = "warning", "Warning"
        ERROR = "error", "Error"
        CRITICAL = "critical", "Critical"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.INFO)
    source = models.CharField(max_length=100)
    event_type = models.CharField(max_length=100)
    message = models.TextField()
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"[{self.severity}] {self.source}: {self.message[:80]}"
