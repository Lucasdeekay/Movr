"""
WebSocket Consumer for Emergency - SOS Alerts

This module provides the EmergencyConsumer for real-time SOS alert broadcasting.

Endpoint: ws://localhost:8000/ws/emergency/?token=<auth_token>

Usage:
------
Connect via WebSocket client:
  ws://localhost:8000/ws/emergency/?token=<token>

Outgoing Messages:
------------------
{
    "type": "sos_alert",
    "alert": {
        "id": "uuid",
        "user": "user@example.com",
        "status": "pending",
        "latitude": 6.5244,
        "longitude": 3.3792,
        "message": "Emergency!",
        "created_at": "2024-01-15T10:30:00Z"
    }
}

{
    "type": "sos_status_update",
    "alert_id": "uuid",
    "status": "acknowledged/resolved"
}
"""
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import AnonymousUser
from rest_framework.authtoken.models import Token
import json
from django.utils import timezone


class EmergencyConsumer(AsyncWebsocketConsumer):
    """
    WebSocket Consumer for emergency SOS alerts.
    
    Endpoint: ws://localhost:8000/ws/emergency/?token=<auth_token>
    
    Handles:
    - SOS alert broadcasts
    - SOS status updates (admin only)
    """
    
    async def connect(self):
        """Handle WebSocket connection."""
        self.user = await self.get_user_from_token()
        if self.user is None or isinstance(self.user, AnonymousUser):
            await self.close()
        else:
            self.group_name = "sos_alerts"
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        """Handle incoming messages."""
        pass

    async def get_user_from_token(self):
        """Extract and validate user from token query parameter."""
        query_string = self.scope['query_string'].decode()
        token_key = None
        for param in query_string.split('&'):
            if param.startswith('token='):
                token_key = param.split('=')[1]
                break
        
        if not token_key:
            return None
            
        try:
            token = await Token.objects.aget(key=token_key)
            return token.user
        except Token.DoesNotExist:
            return None

    async def sos_alert(self, event):
        """Handle incoming SOS alert broadcast."""
        await self.send(text_data=json.dumps({
            'type': 'sos_alert',
            'alert': event['alert'],
        }))

    async def sos_status_update(self, event):
        """Handle SOS status update broadcast."""
        await self.send(text_data=json.dumps({
            'type': 'sos_status_update',
            'alert_id': str(event.get('alert_id', '')),
            'status': event['status'],
        }))
