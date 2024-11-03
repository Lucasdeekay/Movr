from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import AnonymousUser
from rest_framework.authtoken.models import Token
import json
from .models import Route, CustomUser

from django.db.models.signals import post_save
from django.dispatch import receiver
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import Package

'''
void connectToWebSocket(String token) {
  // Replace 'ws://yourserver.com/ws/' with your WebSocket URL
  final channel = WebSocketChannel.connect(
    Uri.parse('ws://yourserver.com/ws/?token=$token'),
  );

  // Listen for messages from the server
  channel.stream.listen(
    (message) {
      print('Received: $message');
    },
    onDone: () {
      print('WebSocket closed');
    },
    onError: (error) {
      print('Error: $error');
    },
  );

  // Send a message to the server (if needed)
  // channel.sink.add('Your message here');

  // Close the WebSocket connection when done
  // channel.sink.close(status.goingAway);
}
'''

class TotalLiveRoutesConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        """
        Handles the WebSocket connection event. Authenticates the user using a token
        and adds the user to a unique group for receiving updates. If authentication
        fails, the connection is closed.

        Parameters:
        None

        Returns:
        None
        """
        self.user = await self.get_user_from_token()
        if self.user is None or isinstance(self.user, AnonymousUser):
            await self.close()
        else:
            self.group_name = f'user_{self.user.id}'  # Unique group for each user
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
            await self.send_live_routes_count()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        # This method can be used to handle incoming messages if needed
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
            'live_routes_count': live_routes_count
        }))

    async def broadcast_live_routes_count(self, count):
        await self.channel_layer.group_send(
            self.group_name,
            {
                'type': 'send_live_routes_count',
                'count': count,
            }
        )

    async def send_live_routes_count(self, event):
        count = event['count']
        await self.send(text_data=json.dumps({
            'live_routes_count': count
        }))


class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope["user"]
        if self.user.is_authenticated:
            # Group name based on user ID or role
            self.group_name = f"movers_{self.user.id}"
            await self.channel_layer.group_add(
                self.group_name,
                self.channel_name
            )
            await self.accept()
        else:
            await self.close()

    async def disconnect(self, close_code):
        if self.user.is_authenticated:
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )

    async def send_notification(self, event):
        await self.send(text_data=json.dumps(event["content"]))


@receiver(post_save, sender=Package)
def notify_movers(sender, instance, created, **kwargs):
    if created:
        # Fetch movers within the specified range
        movers = CustomUser.objects.filter(...)  # Add logic to filter based on range
        channel_layer = get_channel_layer()

        for mover in movers:
            async_to_sync(channel_layer.group_send)(
                f"movers_{mover.id}",
                {
                    "type": "send_notification",
                    "content": {
                        "message": f"New package request from {instance.user.email} to {instance.destination}.",
                        "package_id": instance.id,
                        "location": instance.location,
                        "destination": instance.destination,
                    },
                },
            )