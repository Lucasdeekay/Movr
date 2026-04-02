from django.urls import path
from .consumers import (
    TotalLiveRoutesConsumer, NotificationConsumer, ChatConsumer, PresenceConsumer,
)

"""
WebSocket URL Patterns for Real-Time Features

Endpoints:
-----------
1. ws/live-routes/ - TotalLiveRoutesConsumer
   - Tracks live routes count for authenticated users
   - Query params: ?token=<auth_token>
   - Events: live_routes_count

2. ws/notifications/ - NotificationConsumer  
   - Real-time notifications for users
   - Requires authentication
   - Events: notifications, trip_updates, payment_confirmations, ride_requests, sos_alerts

3. ws/chat/ - ChatConsumer
   - Real-time chat between users
   - Requires authentication
   - Events: chat_message, typing, read_receipt

4. ws/presence/ - PresenceConsumer
   - Online/offline presence and location tracking
   - Requires authentication
   - Events: presence, location

Usage:
------
Connect via WebSocket client:
  ws://localhost:8000/ws/live-routes/?token=<token>
  ws://localhost:8000/ws/notifications/?token=<token>
  ws://localhost:8000/ws/chat/?token=<token>
  ws://localhost:8000/ws/presence/?token=<token>

Message Format (JSON):
---------------------
Outgoing:
  {"type": "live_routes_count", "count": 5}
  {"type": "notification", "title": "...", "message": "..."}
  {"type": "trip_update", "trip_id": "...", "status": "..."}
  {"type": "payment", "reference": "...", "status": "..."}
  {"type": "chat_message", "message": {...}}
  {"type": "presence", "user_id": "...", "is_online": true/false}
  {"type": "location", "user_id": "...", "latitude": ..., "longitude": ...}

Incoming:
  {"type": "chat_message", "conversation_id": "...", "message": "..."}
  {"type": "typing", "conversation_id": "...", "is_typing": true/false}
  {"type": "read_receipt", "message_id": "..."}
  {"type": "location_update", "latitude": ..., "longitude": ...}
"""

websocket_urlpatterns = [
    path('ws/live-routes/', TotalLiveRoutesConsumer.as_asgi(), name='ws-live-routes'),
    path('ws/notifications/', NotificationConsumer.as_asgi(), name='ws-notifications'),
    path('ws/chat/', ChatConsumer.as_asgi(), name='ws-chat'),
    path('ws/presence/', PresenceConsumer.as_asgi(), name='ws-presence'),
]

