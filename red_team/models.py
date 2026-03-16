"""
Red Team Models - Scan results, vulnerabilities, and exploits.
"""

import uuid

from django.db import models
from django.utils import timezone


class ScanResult(models.Model):
    """Stores reconnaissance scan results."""

    class ScanType(models.TextChoices):
        NMAP_TCP = "nmap_tcp", "Nmap TCP Scan"
        NMAP_UDP = "nmap_udp", "Nmap UDP Scan"
        NMAP_VULN = "nmap_vuln", "Nmap Vulnerability Scan"
        NIKTO = "nikto", "Nikto Web Scan"
        GOBUSTER = "gobuster", "Gobuster Directory Scan"
        SERVICE_ENUM = "service_enum", "Service Enumeration"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_type = models.CharField(max_length=20, choices=ScanType.choices)
    target_ip = models.GenericIPAddressField()
    target_port_range = models.CharField(max_length=50, blank=True, default="1-10000")
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.PENDING)
    results = models.JSONField(default=dict, blank=True, help_text="Raw scan output as JSON")
    open_ports = models.JSONField(default=list, blank=True, help_text="List of open port dicts")
    services = models.JSONField(default=list, blank=True, help_text="Discovered services")
    os_detection = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True, default="")
    duration_seconds = models.FloatField(null=True, blank=True)
    round_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["target_ip", "scan_type"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self):
        return f"{self.scan_type} -> {self.target_ip} [{self.status}]"


class Vulnerability(models.Model):
    """Detected vulnerabilities linked to scans."""

    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        INFO = "info", "Informational"

    class DetectionMethod(models.TextChoices):
        CVE_MATCH = "cve_match", "CVE Pattern Match"
        LLM_ANALYSIS = "llm_analysis", "LLM Analysis"
        NMAP_SCRIPT = "nmap_script", "Nmap Script"
        MANUAL = "manual", "Manual"
        ML_DETECTION = "ml_detection", "ML Detection"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name="vulnerabilities")
    cve_id = models.CharField(max_length=20, blank=True, default="", db_index=True)
    title = models.CharField(max_length=300)
    description = models.TextField(blank=True, default="")
    severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.MEDIUM)
    cvss_score = models.FloatField(null=True, blank=True)
    affected_service = models.CharField(max_length=200, blank=True, default="")
    affected_port = models.IntegerField(null=True, blank=True)
    detection_method = models.CharField(max_length=20, choices=DetectionMethod.choices)
    confidence = models.FloatField(default=0.5, help_text="Detection confidence 0.0-1.0")
    remediation = models.TextField(blank=True, default="")
    raw_evidence = models.JSONField(default=dict, blank=True)
    exploitable = models.BooleanField(null=True)
    round_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]
        verbose_name_plural = "Vulnerabilities"
        indexes = [
            models.Index(fields=["severity"]),
            models.Index(fields=["cve_id"]),
        ]

    def __str__(self):
        return f"{self.cve_id or 'Unknown'}: {self.title} ({self.severity})"


class ExploitAttempt(models.Model):
    """Records exploit execution attempts and outcomes."""

    class ExploitType(models.TextChoices):
        METASPLOIT = "metasploit", "Metasploit Module"
        SQLMAP = "sqlmap", "SQLMap Injection"
        CUSTOM = "custom", "Custom Exploit"
        BRUTEFORCE = "bruteforce", "Brute Force"
        FUZZING = "fuzzing", "Fuzzing"

    class Status(models.TextChoices):
        PLANNED = "planned", "Planned"
        RUNNING = "running", "Running"
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"
        BLOCKED = "blocked", "Blocked by Defense"
        ABORTED = "aborted", "Aborted"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.SET_NULL, null=True, blank=True, related_name="exploit_attempts"
    )
    exploit_type = models.CharField(max_length=15, choices=ExploitType.choices)
    target_ip = models.GenericIPAddressField()
    target_port = models.IntegerField(null=True, blank=True)
    target_service = models.CharField(max_length=200, blank=True, default="")
    exploit_module = models.CharField(max_length=300, blank=True, default="", help_text="e.g. exploit/windows/smb/ms17_010_eternalblue")
    parameters = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PLANNED)
    output = models.TextField(blank=True, default="")
    session_obtained = models.BooleanField(default=False)
    access_level = models.CharField(max_length=50, blank=True, default="", help_text="e.g. user, root, system")
    duration_seconds = models.FloatField(null=True, blank=True)
    round_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["target_ip", "status"]),
            models.Index(fields=["exploit_type"]),
        ]

    def __str__(self):
        return f"{self.exploit_type} -> {self.target_ip}:{self.target_port} [{self.status}]"


class AttackPlan(models.Model):
    """LLM-generated attack plans."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_ip = models.GenericIPAddressField()
    scan = models.ForeignKey(ScanResult, on_delete=models.SET_NULL, null=True, blank=True)
    plan_data = models.JSONField(default=dict, help_text="Structured attack plan from LLM")
    plan_text = models.TextField(blank=True, default="", help_text="Human-readable plan summary")
    total_steps = models.IntegerField(default=0)
    completed_steps = models.IntegerField(default=0)
    success_rate = models.FloatField(null=True, blank=True)
    llm_model = models.CharField(max_length=100, blank=True, default="")
    llm_reasoning = models.TextField(blank=True, default="")
    round_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Attack plan for {self.target_ip} ({self.completed_steps}/{self.total_steps} steps)"
