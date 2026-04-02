"""
WebSocket routing for Packages app.

Endpoint: ws://localhost:8000/ws/packages/?token=<auth_token>
"""
from django.urls import path
from .consumers import PackageRideRequestConsumer

websocket_urlpatterns = [
    path('ws/packages/', PackageRideRequestConsumer.as_asgi(), name='ws-packages'),
]
