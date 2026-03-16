"""
Dashboard URLs
"""

from django.urls import path

from dashboard import views

app_name = "dashboard"

urlpatterns = [
    path("", views.DashboardView.as_view(), name="index"),
    path("red-team/", views.RedTeamDashboardView.as_view(), name="red_team"),
    path("blue-team/", views.BlueTeamDashboardView.as_view(), name="blue_team"),
    path("simulations/", views.SimulationDashboardView.as_view(), name="simulations"),
    path("api/dashboard-data/", views.DashboardDataAPIView.as_view(), name="dashboard_data"),
]
