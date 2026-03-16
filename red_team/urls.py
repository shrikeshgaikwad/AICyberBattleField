"""
Red Team API URLs
"""

from django.urls import path

from red_team import views

app_name = "red_team"

urlpatterns = [
    path("scan/", views.StartScanView.as_view(), name="start_scan"),
    path("scans/", views.ScanListView.as_view(), name="scan_list"),
    path("scans/<uuid:scan_id>/", views.ScanDetailView.as_view(), name="scan_detail"),
    path("vulnerabilities/", views.VulnerabilityListView.as_view(), name="vuln_list"),
    path("attack/", views.LaunchAttackView.as_view(), name="launch_attack"),
    path("plans/", views.AttackPlanListView.as_view(), name="plan_list"),
    path("exploits/", views.ExploitListView.as_view(), name="exploit_list"),
    path("status/", views.RedTeamStatusView.as_view(), name="status"),
]
