"""
WebSocket routing for Presence app.

Endpoint: ws://localhost:8000/ws/presence/?token=<auth_token>
"""
from django.urls import path
from .consumers import PresenceConsumer

websocket_urlpatterns = [
    path('ws/presence/', PresenceConsumer.as_asgi(), name='ws-presence'),
]
