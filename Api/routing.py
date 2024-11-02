from django.urls import path
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from .consumers import (
    TotalLiveRoutesConsumer,
)

application = ProtocolTypeRouter({
    # HTTP requests
    'http': URLRouter([

    ]),

    # WebSocket requests
    'websocket': AuthMiddlewareStack(
        URLRouter([
            path('ws/live-routes/', TotalLiveRoutesConsumer.as_asgi()),
        ])
    ),
})