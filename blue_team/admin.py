from django.contrib import admin

from blue_team.models import Alert, DefenseAction, DetectionRule, TrafficLog


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("severity", "source", "status", "title", "source_ip", "confidence", "created_at")
    list_filter = ("severity", "source", "status", "created_at")
    search_fields = ("title", "description", "source_ip")
    readonly_fields = ("id", "created_at")


@admin.register(DefenseAction)
class DefenseActionAdmin(admin.ModelAdmin):
    list_display = ("action_type", "status", "target_ip", "confidence", "auto_generated", "created_at")
    list_filter = ("action_type", "status", "auto_generated")
    readonly_fields = ("id", "created_at")


@admin.register(TrafficLog)
class TrafficLogAdmin(admin.ModelAdmin):
    list_display = ("source_ip", "destination_ip", "destination_port", "protocol", "is_anomalous", "timestamp")
    list_filter = ("protocol", "is_anomalous")
    search_fields = ("source_ip", "destination_ip")
    readonly_fields = ("id", "timestamp")


@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "rule_type", "enabled", "hit_count", "false_positive_count", "auto_generated")
    list_filter = ("rule_type", "enabled", "auto_generated")
    search_fields = ("name", "description")
