from django.contrib import admin

from core.memory import MemoryEntry
from core.models import AgentAction, AIDecision, SystemEvent


@admin.register(AgentAction)
class AgentActionAdmin(admin.ModelAdmin):
    list_display = ("agent_type", "agent_name", "action_name", "target", "success", "created_at")
    list_filter = ("agent_type", "success", "created_at")
    search_fields = ("agent_name", "action_name", "target")
    readonly_fields = ("id", "created_at")


@admin.register(AIDecision)
class AIDecisionAdmin(admin.ModelAdmin):
    list_display = ("agent_type", "agent_name", "decision", "confidence", "outcome_success", "created_at")
    list_filter = ("agent_type", "outcome_success", "created_at")
    search_fields = ("decision", "reasoning")
    readonly_fields = ("id", "created_at")


@admin.register(SystemEvent)
class SystemEventAdmin(admin.ModelAdmin):
    list_display = ("severity", "source", "event_type", "message", "created_at")
    list_filter = ("severity", "source", "event_type", "created_at")
    search_fields = ("message",)
    readonly_fields = ("id", "created_at")


@admin.register(MemoryEntry)
class MemoryEntryAdmin(admin.ModelAdmin):
    list_display = ("agent_type", "agent_name", "memory_type", "action_taken", "success", "reward", "strength", "created_at")
    list_filter = ("agent_type", "memory_type", "success", "created_at")
    search_fields = ("action_taken", "lesson", "outcome_details")
    readonly_fields = ("id", "context_hash", "created_at")

