"""
WebSocket routing for Emergency app.

Endpoint: ws://localhost:8000/ws/emergency/?token=<auth_token>
"""
from django.urls import path
from .consumers import EmergencyConsumer

websocket_urlpatterns = [
    path('ws/emergency/', EmergencyConsumer.as_asgi(), name='ws-emergency'),
]
