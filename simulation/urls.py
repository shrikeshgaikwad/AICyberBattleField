"""
Simulation API URLs
"""

from django.urls import path

from simulation import views

app_name = "simulation"

urlpatterns = [
    path("create/", views.CreateSimulationView.as_view(), name="create"),
    path("run/<uuid:sim_id>/", views.RunSimulationView.as_view(), name="run"),
    path("list/", views.SimulationListView.as_view(), name="list"),
    path("<uuid:sim_id>/", views.SimulationDetailView.as_view(), name="detail"),
    path("<uuid:sim_id>/rounds/", views.RoundListView.as_view(), name="rounds"),
]
