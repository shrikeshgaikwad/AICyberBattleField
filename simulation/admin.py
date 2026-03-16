from django.contrib import admin

from simulation.models import SimulationConfig, SimulationRound


@admin.register(SimulationConfig)
class SimulationConfigAdmin(admin.ModelAdmin):
    list_display = ("name", "status", "total_rounds_completed", "max_rounds", "created_at")
    list_filter = ("status",)
    readonly_fields = ("id", "created_at")


@admin.register(SimulationRound)
class SimulationRoundAdmin(admin.ModelAdmin):
    list_display = (
        "simulation", "round_number", "status", "target_ip",
        "red_team_score", "blue_team_score", "duration_seconds",
    )
    list_filter = ("status",)
    readonly_fields = ("id",)
