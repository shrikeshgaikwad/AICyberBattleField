"""
Blue Team API URLs
"""

from django.urls import path

from blue_team import views

app_name = "blue_team"

urlpatterns = [
    path("alerts/", views.AlertListView.as_view(), name="alert_list"),
    path("actions/", views.DefenseActionListView.as_view(), name="action_list"),
    path("traffic/", views.TrafficLogView.as_view(), name="traffic_log"),
    path("rules/", views.DetectionRuleListView.as_view(), name="rule_list"),
    path("defend/", views.RunDefenseView.as_view(), name="run_defense"),
    path("status/", views.BlueTeamStatusView.as_view(), name="status"),
]
