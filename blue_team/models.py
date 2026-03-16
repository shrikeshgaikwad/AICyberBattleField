"""
Blue Team Models - Intrusion detection, alerts, and defense actions.
"""

import uuid

from django.db import models
from django.utils import timezone


class Alert(models.Model):
    """Security alerts raised by the defensive AI."""

    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        INFO = "info", "Informational"

    class Source(models.TextChoices):
        IDS = "ids", "Intrusion Detection System"
        ANOMALY_ML = "anomaly_ml", "ML Anomaly Detection"
        SIGNATURE = "signature", "Signature Match"
        LOG_ANALYSIS = "log_analysis", "Log Analysis"
        TRAFFIC_MONITOR = "traffic_monitor", "Traffic Monitor"

    class Status(models.TextChoices):
        NEW = "new", "New"
        INVESTIGATING = "investigating", "Investigating"
        CONFIRMED = "confirmed", "Confirmed"
        FALSE_POSITIVE = "false_positive", "False Positive"
        RESOLVED = "resolved", "Resolved"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    severity = models.CharField(max_length=10, choices=Severity.choices)
    source = models.CharField(max_length=20, choices=Source.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.NEW)
    title = models.CharField(max_length=300)
    description = models.TextField(blank=True, default="")
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, blank=True, default="")
    signature_id = models.CharField(max_length=50, blank=True, default="")
    confidence = models.FloatField(default=0.5)
    raw_data = models.JSONField(default=dict, blank=True)
    round_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["severity", "status"]),
            models.Index(fields=["source_ip"]),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.title} from {self.source_ip}"


class DefenseAction(models.Model):
    """Automated defense actions taken in response to threats."""

    class ActionType(models.TextChoices):
        BLOCK_IP = "block_ip", "Block IP Address"
        RATE_LIMIT = "rate_limit", "Rate Limit"
        HONEYPOT = "honeypot", "Deploy Honeypot"
        ISOLATE = "isolate", "Isolate Host"
        PATCH = "patch", "Apply Patch"
        ALERT_ADMIN = "alert_admin", "Alert Administrator"
        UPDATE_RULES = "update_rules", "Update Detection Rules"
        QUARANTINE = "quarantine", "Quarantine"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        ACTIVE = "active", "Active"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        ROLLED_BACK = "rolled_back", "Rolled Back"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    alert = models.ForeignKey(Alert, on_delete=models.SET_NULL, null=True, blank=True, related_name="actions")
    action_type = models.CharField(max_length=15, choices=ActionType.choices)
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.PENDING)
    target_ip = models.GenericIPAddressField(null=True, blank=True)
    parameters = models.JSONField(default=dict, blank=True)
    result = models.TextField(blank=True, default="")
    reasoning = models.TextField(blank=True, default="")
    confidence = models.FloatField(default=0.5)
    auto_generated = models.BooleanField(default=True)
    duration_seconds = models.FloatField(null=True, blank=True)
    round_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["action_type", "status"]),
        ]

    def __str__(self):
        return f"{self.action_type} against {self.target_ip} [{self.status}]"


class TrafficLog(models.Model):
    """Network traffic log entries for monitoring."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_port = models.IntegerField(null=True, blank=True)
    destination_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, default="TCP")
    packet_size = models.IntegerField(default=0)
    flags = models.CharField(max_length=20, blank=True, default="")
    payload_preview = models.TextField(blank=True, default="", max_length=500)
    is_anomalous = models.BooleanField(default=False)
    anomaly_score = models.FloatField(null=True, blank=True)
    round_id = models.UUIDField(null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["source_ip", "timestamp"]),
            models.Index(fields=["is_anomalous"]),
        ]

    def __str__(self):
        return f"{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}"


class DetectionRule(models.Model):
    """Custom detection rules (YARA/Snort-style)."""

    class RuleType(models.TextChoices):
        SIGNATURE = "signature", "Signature"
        ANOMALY = "anomaly", "Anomaly Threshold"
        BEHAVIORAL = "behavioral", "Behavioral Pattern"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200, unique=True)
    rule_type = models.CharField(max_length=15, choices=RuleType.choices)
    description = models.TextField(blank=True, default="")
    rule_content = models.TextField(help_text="Rule definition (YARA/Snort syntax or JSON)")
    enabled = models.BooleanField(default=True)
    auto_generated = models.BooleanField(default=False)
    hit_count = models.IntegerField(default=0)
    false_positive_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-hit_count"]

    def __str__(self):
        return f"[{self.rule_type}] {self.name} ({'enabled' if self.enabled else 'disabled'})"
