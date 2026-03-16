from django.contrib import admin

from red_team.models import AttackPlan, ExploitAttempt, ScanResult, Vulnerability


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ("scan_type", "target_ip", "status", "duration_seconds", "created_at")
    list_filter = ("scan_type", "status", "created_at")
    search_fields = ("target_ip",)
    readonly_fields = ("id", "created_at")


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "title", "severity", "affected_service", "affected_port", "exploitable", "created_at")
    list_filter = ("severity", "detection_method", "exploitable")
    search_fields = ("cve_id", "title", "description")
    readonly_fields = ("id", "created_at")


@admin.register(ExploitAttempt)
class ExploitAttemptAdmin(admin.ModelAdmin):
    list_display = ("exploit_type", "target_ip", "target_port", "status", "session_obtained", "created_at")
    list_filter = ("exploit_type", "status", "session_obtained")
    search_fields = ("target_ip", "exploit_module")
    readonly_fields = ("id", "created_at")


@admin.register(AttackPlan)
class AttackPlanAdmin(admin.ModelAdmin):
    list_display = ("target_ip", "total_steps", "completed_steps", "success_rate", "created_at")
    readonly_fields = ("id", "created_at")
