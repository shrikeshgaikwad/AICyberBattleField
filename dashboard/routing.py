"""
Dashboard WebSocket URL Routing
"""

from django.urls import re_path
from dashboard.consumers import BattlefieldConsumer

websocket_urlpatterns = [
    re_path(r"ws/battlefield/$", BattlefieldConsumer.as_asgi()),
]
