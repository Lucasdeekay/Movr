"""
WebSocket Consumer for Presence - Online/Offline Status & Location

This module provides the PresenceConsumer for real-time presence tracking.

Endpoint: ws://localhost:8000/ws/presence/?token=<auth_token>

Usage:
------
Connect via WebSocket client:
  ws://localhost:8000/ws/presence/?token=<token>

Incoming Messages:
------------------
{
    "type": "location_update",
    "latitude": 6.5244,
    "longitude": 3.3792
}

Outgoing Messages:
------------------
{
    "type": "presence",
    "user_id": "uuid",
    "email": "user@example.com",
    "is_online": true
}

{
    "type": "location",
    "user_id": "uuid",
    "latitude": 6.5244,
    "longitude": 3.3792
}
"""
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import AnonymousUser
from rest_framework.authtoken.models import Token
import json
from django.utils import timezone


class PresenceConsumer(AsyncWebsocketConsumer):
    """
    WebSocket Consumer for presence tracking.
    
    Endpoint: ws://localhost:8000/ws/presence/?token=<auth_token>
    
    Handles:
    - Online/offline status
    - Location updates
    - Presence broadcasts
    """
    
    async def connect(self):
        """Handle WebSocket connection."""
        self.user = await self.get_user_from_token()
        if self.user is None or isinstance(self.user, AnonymousUser):
            await self.close()
        else:
            self.group_name = "presence_updates"
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
            
            presence, _ = await self.get_or_create_presence()
            presence.is_online = True
            presence.last_seen = timezone.now()
            presence.save()
            
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "presence_update",
                    "user_id": str(self.user.id),
                    "email": self.user.email,
                    "is_online": True,
                }
            )

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        if hasattr(self, 'user') and self.user and not isinstance(self.user, AnonymousUser):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
            
            try:
                presence = await self.get_or_create_presence()[0]
                presence.is_online = False
                presence.save()
                
                await self.channel_layer.group_send(
                    self.group_name,
                    {
                        "type": "presence_update",
                        "user_id": str(self.user.id),
                        "email": self.user.email,
                        "is_online": False,
                    }
                )
            except:
                pass

    async def receive(self, text_data):
        """Handle incoming messages."""
        data = json.loads(text_data)
        
        if data.get('type') == 'location_update':
            await self.handle_location_update(data)

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

    async def get_or_create_presence(self):
        """Get or create user presence."""
        from Presence.models import UserPresence
        presence, created = await UserPresence.objects.aget_or_create(user=self.user)
        return presence, created

    async def handle_location_update(self, data):
        """Handle location update."""
        try:
            presence, _ = await self.get_or_create_presence()
            presence.current_latitude = data.get('latitude')
            presence.current_longitude = data.get('longitude')
            presence.location_updated_at = timezone.now()
            presence.save()
            
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "location_broadcast",
                    "user_id": str(self.user.id),
                    "latitude": data.get('latitude'),
                    "longitude": data.get('longitude'),
                }
            )
        except:
            pass

    async def presence_update(self, event):
        """Handle presence update broadcast."""
        await self.send(text_data=json.dumps({
            'type': 'presence',
            'user_id': event['user_id'],
            'email': event.get('email'),
            'is_online': event['is_online']
        }))

    async def location_broadcast(self, event):
        """Handle location broadcast."""
        await self.send(text_data=json.dumps({
            'type': 'location',
            'user_id': event['user_id'],
            'latitude': event['latitude'],
            'longitude': event['longitude'],
        }))
