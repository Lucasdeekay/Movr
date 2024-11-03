from django.urls import path
from .consumers import (
    TotalLiveRoutesConsumer, NotificationConsumer,
)

websocket_urlpatterns = [
    path('ws/live-routes/', TotalLiveRoutesConsumer.as_asgi()),
    path('ws/notifications/', NotificationConsumer.as_asgi()),
]

