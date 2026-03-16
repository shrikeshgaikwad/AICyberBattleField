"""
Simulation Models - Rounds, metrics, and configurations.
"""

import uuid

from django.db import models
from django.utils import timezone


class SimulationConfig(models.Model):
    """Configuration for a simulation run."""

    class Status(models.TextChoices):
        CREATED = "created", "Created"
        RUNNING = "running", "Running"
        PAUSED = "paused", "Paused"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, default="")
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.CREATED)
    target_ips = models.JSONField(default=list, help_text="List of target IPs")
    max_rounds = models.IntegerField(default=10)
    round_duration_seconds = models.IntegerField(default=300)
    red_team_config = models.JSONField(default=dict, blank=True)
    blue_team_config = models.JSONField(default=dict, blank=True)
    total_rounds_completed = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Simulation"
        verbose_name_plural = "Simulations"

    def __str__(self):
        return f"{self.name} [{self.status}] ({self.total_rounds_completed}/{self.max_rounds} rounds)"


class SimulationRound(models.Model):
    """Individual simulation round."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RED_TEAM = "red_team", "Red Team Active"
        BLUE_TEAM = "blue_team", "Blue Team Active"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    simulation = models.ForeignKey(SimulationConfig, on_delete=models.CASCADE, related_name="rounds")
    round_number = models.IntegerField()
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.PENDING)
    target_ip = models.GenericIPAddressField(null=True, blank=True)

    # Red Team results
    red_team_scans = models.IntegerField(default=0)
    red_team_vulns_found = models.IntegerField(default=0)
    red_team_exploits_attempted = models.IntegerField(default=0)
    red_team_exploits_succeeded = models.IntegerField(default=0)

    # Blue Team results
    blue_team_alerts = models.IntegerField(default=0)
    blue_team_detections = models.IntegerField(default=0)
    blue_team_blocks = models.IntegerField(default=0)
    blue_team_false_positives = models.IntegerField(default=0)

    # Timing
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)

    # Scores
    red_team_score = models.FloatField(default=0.0)
    blue_team_score = models.FloatField(default=0.0)

    class Meta:
        ordering = ["simulation", "round_number"]
        unique_together = ("simulation", "round_number")

    def __str__(self):
        return f"Round {self.round_number}: Red={self.red_team_score:.1f} Blue={self.blue_team_score:.1f}"
