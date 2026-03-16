"""
Cyber Battlefield - URL Configuration
"""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/red-team/", include("red_team.urls")),
    path("api/blue-team/", include("blue_team.urls")),
    path("api/simulation/", include("simulation.urls")),
    path("", include("dashboard.urls")),
]
