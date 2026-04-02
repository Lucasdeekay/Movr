"""
WebSocket routing for Profile app - Notifications.

Endpoint: ws://localhost:8000/ws/notifications/?token=<auth_token>
"""
from django.urls import path
from .consumers import NotificationConsumer

websocket_urlpatterns = [
    path('ws/notifications/', NotificationConsumer.as_asgi(), name='ws-notifications'),
]
