"""
WebSocket routing for Chat app.

Endpoint: ws://localhost:8000/ws/chat/?token=<auth_token>
"""
from django.urls import path
from .consumers import ChatConsumer

websocket_urlpatterns = [
    path('ws/chat/', ChatConsumer.as_asgi(), name='ws-chat'),
]
