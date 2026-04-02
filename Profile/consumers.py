"""
WebSocket Consumer for Profile - Real-time Notifications

This module provides the NotificationConsumer for real-time notifications.

Endpoint: ws://localhost:8000/ws/notifications/?token=<auth_token>

Usage:
------
Connect via WebSocket client:
  ws://localhost:8000/ws/notifications/?token=<token>

Outgoing Messages:
------------------
{
    "type": "notification",
    "title": "New Notification",
    "message": "You have a new message"
}

{
    "type": "trip_update",
    "trip_id": "uuid",
    "status": "in_transit",
    "eta": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:00:00Z"
}

{
    "type": "payment",
    "reference": "uuid",
    "status": "completed",
    "amount": "5000.00"
}

{
    "type": "ride_request",
    "package_id": "uuid",
    "location": "Lagos",
    "destination": "Abuja",
    "range_radius": "10"
}

{
    "type": "sos_alert",
    "alert": {
        "id": "uuid",
        "user": "email@example.com",
        "location": "...",
        "status": "pending"
    }
}
"""
from channels.generic.websocket import AsyncWebsocketConsumer
import json
from django.utils import timezone


class NotificationConsumer(AsyncWebsocketConsumer):
    """
    WebSocket Consumer for real-time notifications.
    
    Endpoint: ws://localhost:8000/ws/notifications/?token=<token>
    
    Handles:
    - General notifications
    - Trip status updates
    - Payment confirmations
    - Ride request broadcasts
    - SOS alerts
    
    Authentication:
    --------------
    Pass token as query parameter:
      ws://localhost:8000/ws/notifications/?token=<your_token>
    """
    
    async def connect(self):
        """Handle WebSocket connection."""
        from django.contrib.auth.models import AnonymousUser
        
        self.user = self.scope.get("user")
        if self.user and self.user.is_authenticated and not isinstance(self.user, AnonymousUser):
            self.group_name = f"user_{self.user.id}"
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
            
            await self.update_presence_status(True)
        else:
            await self.close()

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        if hasattr(self, 'user') and self.user and self.user.is_authenticated:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
            await self.update_presence_status(False)

    async def update_presence_status(self, is_online):
        """Update user presence status."""
        try:
            from Presence.models import UserPresence
            presence, _ = await UserPresence.objects.aget_or_create(user=self.user)
            presence.is_online = is_online
            presence.last_seen = timezone.now()
            await presence.asave()
        except Exception:
            pass

    async def send_notification(self, event):
        """Handle notification message."""
        await self.send(text_data=json.dumps(event["content"]))

    async def trip_status_update(self, event):
        """Handle trip status update."""
        await self.send(text_data=json.dumps({
            'type': 'trip_update',
            'trip_id': str(event['trip_id']),
            'status': event['status'],
            'eta': event.get('eta'),
            'updated_at': event.get('updated_at'),
        }))

    async def payment_update(self, event):
        """Handle payment update."""
        await self.send(text_data=json.dumps({
            'type': 'payment',
            'reference': event['reference'],
            'status': event['status'],
            'amount': str(event['amount']),
        }))

    async def ride_request(self, event):
        """Handle ride request broadcast."""
        await self.send(text_data=json.dumps({
            'type': 'ride_request',
            'package_id': str(event['package_id']),
            'location': event['location'],
            'destination': event['destination'],
            'range_radius': str(event.get('range_radius', '')),
        }))

    async def sos_alert(self, event):
        """Handle SOS alert."""
        await self.send(text_data=json.dumps({
            'type': 'sos_alert',
            'alert': event['alert'],
        }))
