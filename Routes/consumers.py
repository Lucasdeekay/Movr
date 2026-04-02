"""
WebSocket Consumer for Routes - Live Routes Count

This module provides the TotalLiveRoutesConsumer for real-time tracking
of live routes count via WebSocket connections.

Endpoint: ws://localhost:8000/ws/live-routes/?token=<auth_token>

Usage:
------
Connect via WebSocket client:
  ws://localhost:8000/ws/live-routes/?token=<token>

Message Format (Outgoing):
--------------------------
{
    "type": "live_routes_count",
    "count": 5
}

Connect Example (Python):
-------------------------
import websocket
ws = websocket.create_connection("ws://localhost:8000/ws/live-routes/?token=<token>")
ws.recv()  # Returns: {"type": "live_routes_count", "count": 5}

Connect Example (JavaScript):
-----------------------------
const ws = new WebSocket('ws://localhost:8000/ws/live-routes/?token=<token>');
ws.onmessage = (event) => { console.log(JSON.parse(event.data)); };
"""
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import AnonymousUser
from rest_framework.authtoken.models import Token
import json
from django.utils import timezone


class TotalLiveRoutesConsumer(AsyncWebsocketConsumer):
    """
    WebSocket Consumer for tracking live routes count.
    
    Endpoint: ws://localhost:8000/ws/live-routes/?token=<auth_token>
    
    Functionality:
    - Authenticates user via token query parameter
    - Adds user to a unique group based on user ID
    - Sends live routes count on connect
    - Broadcasts count updates to the user
    
    Outgoing Messages:
    - {"type": "live_routes_count", "count": <number>}
    
    Authentication:
    --------------
    Pass token as query parameter:
      ws://localhost:8000/ws/live-routes/?token=<your_token>
    
    Error Codes:
    ------------
    - 4001: Invalid or missing token
    - 4002: User not found
    """
    
    async def connect(self):
        """
        Handle WebSocket connection.
        
        Authenticates user and joins them to their personal group.
        """
        self.user = await self.get_user_from_token()
        if self.user is None or isinstance(self.user, AnonymousUser):
            await self.close()
        else:
            self.group_name = f'user_{self.user.id}'
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
            await self.send_live_routes_count()

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        """Handle incoming messages (no-op for this consumer)."""
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

    async def get_live_routes_count(self):
        """Get count of live routes for the authenticated user."""
        from Routes.models import Route
        return await Route.objects.filter(user=self.user, is_live=True).acount()

    async def send_live_routes_count(self):
        """Send live routes count to client."""
        live_routes_count = await self.get_live_routes_count()
        await self.send(text_data=json.dumps({
            'type': 'live_routes_count',
            'count': live_routes_count
        }))

    async def broadcast_live_routes_count(self, event):
        """Handle broadcast of live routes count update."""
        count = event['count']
        await self.send(text_data=json.dumps({
            'type': 'live_routes_count',
            'count': count
        }))
