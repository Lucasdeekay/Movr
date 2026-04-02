from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import AnonymousUser
from rest_framework.authtoken.models import Token
import json
from Routes.models import Route
from Packages.models import Package
from Chat.models import ChatConversation, ChatMessage
from Presence.models import UserPresence
from .models import CustomUser

from django.db.models.signals import post_save
from django.dispatch import receiver
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.utils import timezone

'''
WebSocket Connection Examples:
-----------------------------

1. Python (websocket-client):
   import websocket
   ws = websocket.create_connection("ws://localhost:8000/ws/notifications/?token=<token>")
   ws.recv()  # Receive messages

2. JavaScript:
   const ws = new WebSocket('ws://localhost:8000/ws/notifications/?token=<token>');
   ws.onmessage = (event) => { console.log(JSON.parse(event.data)); };

3. Dart/Flutter:
   final channel = WebSocketChannel.connect(
     Uri.parse('ws://yourserver.com/ws/?token=$token'),
   );

Message Types:
-------------
- notification: {"type": "notification", "title": "...", "message": "..."}
- trip_update: {"type": "trip_update", "trip_id": "...", "status": "..."}
- payment: {"type": "payment", "reference": "...", "status": "..."}
- chat_message: {"type": "chat_message", "message": "...", "sender": "..."}
- presence: {"type": "presence", "user_id": "...", "status": "online/offline"}
- location: {"type": "location", "user_id": "...", "lat": ..., "lng": ...}
- eta_update: {"type": "eta_update", "trip_id": "...", "eta_seconds": ...}
- sos_alert: {"type": "sos_alert", "alert": {...}}
'''

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
    """
    async def connect(self):
        self.user = await self.get_user_from_token()
        if self.user is None or isinstance(self.user, AnonymousUser):
            await self.close()
        else:
            self.group_name = f'user_{self.user.id}'
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
            await self.send_live_routes_count()

    async def disconnect(self, close_code):
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        pass

    async def get_user_from_token(self):
        token_key = self.scope['query_string'].decode().split('=')[1]
        try:
            token = await Token.objects.aget(key=token_key)
            return token.user
        except Token.DoesNotExist:
            return None

    async def get_live_routes_count(self):
        return await Route.objects.filter(user=self.user, is_live=True).acount()

    async def send_live_routes_count(self):
        live_routes_count = await self.get_live_routes_count()
        await self.send(text_data=json.dumps({
            'type': 'live_routes_count',
            'count': live_routes_count
        }))

    async def broadcast_live_routes_count(self, event):
        count = event['count']
        await self.send(text_data=json.dumps({
            'type': 'live_routes_count',
            'count': count
        }))


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
    """
    async def connect(self):
        self.user = self.scope.get("user")
        if self.user and self.user.is_authenticated:
            self.group_name = f"user_{self.user.id}"
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
            
            presence, _ = UserPresence.objects.get_or_create(user=self.user)
            presence.is_online = True
            presence.last_seen = timezone.now()
            presence.save()
        else:
            await self.close()

    async def disconnect(self, close_code):
        if hasattr(self, 'user') and self.user and self.user.is_authenticated:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
            
            try:
                presence = UserPresence.objects.get(user=self.user)
                presence.is_online = False
                presence.save()
            except UserPresence.DoesNotExist:
                pass

    async def send_notification(self, event):
        await self.send(text_data=json.dumps(event["content"]))

    async def trip_status_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'trip_update',
            'trip_id': str(event['trip_id']),
            'status': event['status'],
            'eta': event.get('eta'),
            'updated_at': event.get('updated_at'),
        }))

    async def payment_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'payment',
            'reference': event['reference'],
            'status': event['status'],
            'amount': str(event['amount']),
        }))

    async def ride_request(self, event):
        await self.send(text_data=json.dumps({
            'type': 'ride_request',
            'package_id': str(event['package_id']),
            'location': event['location'],
            'destination': event['destination'],
            'range_radius': str(event.get('range_radius', '')),
        }))

    async def sos_alert(self, event):
        await self.send(text_data=json.dumps({
            'type': 'sos_alert',
            'alert': event['alert'],
        }))


class ChatConsumer(AsyncWebsocketConsumer):
    """
    WebSocket Consumer for real-time chat.
    
    Endpoint: ws://localhost:8000/ws/chat/?token=<token>
    
    Handles:
    - Send/receive chat messages
    - Typing indicators
    - Read receipts
    """
    async def connect(self):
        self.user = self.scope.get("user")
        if self.user and self.user.is_authenticated:
            self.group_name = f"chat_{self.user.id}"
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
        else:
            await self.close()

    async def disconnect(self, close_code):
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        data = json.loads(text_data)
        message_type = data.get('type')
        
        if message_type == 'chat_message':
            await self.handle_chat_message(data)
        elif message_type == 'typing':
            await self.handle_typing(data)
        elif message_type == 'read_receipt':
            await self.handle_read_receipt(data)

    async def handle_chat_message(self, data):
        conversation_id = data.get('conversation_id')
        message = data.get('message')
        
        try:
            conversation = ChatConversation.objects.get(id=conversation_id)
            if self.user not in conversation.participants.all():
                return
            
            chat_message = ChatMessage.objects.create(
                conversation=conversation,
                sender=self.user,
                message=message
            )
            
            for participant in conversation.participants.all():
                if participant.id != self.user.id:
                    await self.channel_layer.group_send(
                        f"user_{participant.id}",
                        {
                            "type": "chat_message",
                            "message": {
                                "id": str(chat_message.id),
                                "conversation_id": str(conversation.id),
                                "sender": self.user.email,
                                "message": message,
                                "created_at": chat_message.created_at.isoformat(),
                            }
                        }
                    )
        except ChatConversation.DoesNotExist:
            pass

    async def handle_typing(self, data):
        conversation_id = data.get('conversation_id')
        await self.channel_layer.group_send(
            f"chat_{conversation_id}",
            {
                "type": "typing_indicator",
                "user_id": str(self.user.id),
                "is_typing": data.get('is_typing', True),
            }
        )

    async def handle_read_receipt(self, data):
        message_id = data.get('message_id')
        try:
            message = ChatMessage.objects.get(id=message_id)
            message.is_read = True
            message.read_at = timezone.now()
            message.save()
            
            await self.channel_layer.group_send(
                f"user_{message.sender_id}",
                {
                    "type": "read_receipt",
                    "message_id": str(message_id),
                }
            )
        except ChatMessage.DoesNotExist:
            pass

    async def chat_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'chat_message',
            'message': event['message']
        }))

    async def typing_indicator(self, event):
        await self.send(text_data=json.dumps({
            'type': 'typing',
            'user_id': event['user_id'],
            'is_typing': event['is_typing']
        }))

    async def read_receipt(self, event):
        await self.send(text_data=json.dumps({
            'type': 'read_receipt',
            'message_id': event['message_id']
        }))


class PresenceConsumer(AsyncWebsocketConsumer):
    """
    WebSocket Consumer for presence tracking.
    
    Endpoint: ws://localhost:8000/ws/presence/?token=<token>
    
    Handles:
    - Online/offline status
    - Location updates
    - Presence broadcasts
    """
    async def connect(self):
        self.user = self.scope.get("user")
        if self.user and self.user.is_authenticated:
            self.group_name = "presence_updates"
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
            
            presence, _ = UserPresence.objects.get_or_create(user=self.user)
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
        else:
            await self.close()

    async def disconnect(self, close_code):
        if hasattr(self, 'user') and self.user and self.user.is_authenticated:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
            
            try:
                presence = UserPresence.objects.get(user=self.user)
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
            except UserPresence.DoesNotExist:
                pass

    async def receive(self, text_data):
        data = json.loads(text_data)
        
        if data.get('type') == 'location_update':
            try:
                presence = UserPresence.objects.get(user=self.user)
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
            except UserPresence.DoesNotExist:
                pass

    async def presence_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'presence',
            'user_id': event['user_id'],
            'email': event.get('email'),
            'is_online': event['is_online']
        }))

    async def location_broadcast(self, event):
        await self.send(text_data=json.dumps({
            'type': 'location',
            'user_id': event['user_id'],
            'latitude': event['latitude'],
            'longitude': event['longitude'],
        }))


@receiver(post_save, sender=Package)
def notify_movers(sender, instance, created, **kwargs):
    if created:
        channel_layer = get_channel_layer()
        
        from .models import UserPresence
        nearby_presence = UserPresence.objects.filter(
            is_online=True,
            current_latitude__isnull=False,
            current_longitude__isnull=False,
        )
        
        if instance.location_latitude and instance.location_longitude and instance.range_radius:
            radius = float(instance.range_radius)
            nearby_presence = nearby_presence.filter(
                current_latitude__gte=float(instance.location_latitude) - radius,
                current_latitude__lte=float(instance.location_latitude) + radius,
                current_longitude__gte=float(instance.location_longitude) - radius,
                current_longitude__lte=float(instance.location_longitude) + radius,
            )
        
        for presence in nearby_presence:
            async_to_sync(channel_layer.group_send)(
                f"user_{presence.user.id}",
                {
                    "type": "ride_request",
                    "package_id": str(instance.id),
                    "location": instance.location,
                    "destination": instance.destination,
                    "range_radius": str(instance.range_radius) if instance.range_radius else None,
                },
            )