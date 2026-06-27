"""
Cyber Battlefield - ASGI Configuration
Supports HTTP + WebSocket for real-time dashboard updates.
"""

import os
import logging

from channels.routing import ProtocolTypeRouter
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cyberbattlefield.settings")

django_asgi_app = get_asgi_application()

logger = logging.getLogger(__name__)

# Build protocol router — add WebSocket only if channels supports it
protocols = {
    "http": django_asgi_app,
}

try:
    from channels.auth import AuthMiddlewareStack
    from channels.routing import URLRouter
    from dashboard.routing import websocket_urlpatterns

    protocols["websocket"] = AuthMiddlewareStack(
        URLRouter(websocket_urlpatterns)
    )
    logger.info("WebSocket support enabled")
except ImportError as e:
    logger.warning(f"WebSocket support disabled (missing dependency): {e}")
except Exception as e:
    logger.warning(f"WebSocket support disabled: {e}")

application = ProtocolTypeRouter(protocols)
