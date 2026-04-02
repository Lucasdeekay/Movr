"""
WebSocket routing for Routes app.

This module defines WebSocket URL patterns for the Routes module,
specifically for tracking live routes count.

Endpoint: ws://localhost:8000/ws/routes/?token=<auth_token>

Usage:
------
Connect via WebSocket:
  ws://localhost:8000/ws/routes/?token=<token>

Messages:
---------
Outgoing:
  {"type": "live_routes_count", "count": 5}
  {"type": "route_status", "route_id": "...", "is_live": true}
"""
from django.urls import path
from .consumers import TotalLiveRoutesConsumer

websocket_urlpatterns = [
    path('ws/routes/', TotalLiveRoutesConsumer.as_asgi(), name='ws-routes'),
]
