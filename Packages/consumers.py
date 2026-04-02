"""
WebSocket Consumer for Packages - Ride Requests

This module provides the PackageRideRequestConsumer for real-time
ride request notifications to movers.

Endpoint: ws://localhost:8000/ws/packages/?token=<auth_token>

Usage:
------
Connect via WebSocket client:
  ws://localhost:8000/ws/packages/?token=<token>

Message Format (Outgoing):
--------------------------
{
    "type": "ride_request",
    "package_id": "uuid",
    "location": "Lagos",
    "destination": "Abuja",
    "range_radius": "10.00"
}
"""
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import AnonymousUser
from rest_framework.authtoken.models import Token
import json
from django.utils import timezone


class PackageRideRequestConsumer(AsyncWebsocketConsumer):
    """
    WebSocket Consumer for real-time ride request notifications.
    
    Endpoint: ws://localhost:8000/ws/packages/?token=<auth_token>
    
    Functionality:
    - Authenticates user via token query parameter
    - Sends ride requests when new packages are submitted nearby
    - Broadcasts package status updates
    
    Outgoing Messages:
    - {"type": "ride_request", "package_id": "...", "location": "...", "destination": "..."}
    - {"type": "trip_update", "package_id": "...", "status": "..."}
    """
    
    async def connect(self):
        """Handle WebSocket connection."""
        self.user = await self.get_user_from_token()
        if self.user is None or isinstance(self.user, AnonymousUser):
            await self.close()
        else:
            self.group_name = f'packages_{self.user.id}'
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

    async def ride_request(self, event):
        """Handle incoming ride request broadcast."""
        await self.send(text_data=json.dumps({
            'type': 'ride_request',
            'package_id': str(event['package_id']),
            'location': event['location'],
            'destination': event['destination'],
            'range_radius': str(event.get('range_radius', '')),
        }))

    async def trip_status_update(self, event):
        """Handle trip status update broadcast."""
        await self.send(text_data=json.dumps({
            'type': 'trip_update',
            'package_id': str(event.get('package_id', '')),
            'status': event['status'],
            'eta': event.get('eta'),
        }))
