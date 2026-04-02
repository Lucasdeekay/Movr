"""
WebSocket Consumer for Chat - Real-time Messaging

This module provides the ChatConsumer for real-time chat messaging.

Endpoint: ws://localhost:8000/ws/chat/?token=<auth_token>

Usage:
------
Connect via WebSocket client:
  ws://localhost:8000/ws/chat/?token=<token>

Incoming Messages:
------------------
{
    "type": "chat_message",
    "conversation_id": "uuid",
    "message": "Hello!"
}

{
    "type": "typing",
    "conversation_id": "uuid",
    "is_typing": true
}

{
    "type": "read_receipt",
    "message_id": "uuid"
}

Outgoing Messages:
------------------
{
    "type": "chat_message",
    "message": {
        "id": "uuid",
        "conversation_id": "uuid",
        "sender": "email@example.com",
        "message": "Hello!",
        "created_at": "2024-01-15T10:30:00Z"
    }
}

{
    "type": "typing",
    "user_id": "uuid",
    "is_typing": true/false
}

{
    "type": "read_receipt",
    "message_id": "uuid"
}
"""
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import AnonymousUser
from rest_framework.authtoken.models import Token
import json
from django.utils import timezone


class ChatConsumer(AsyncWebsocketConsumer):
    """
    WebSocket Consumer for real-time chat messaging.
    
    Endpoint: ws://localhost:8000/ws/chat/?token=<auth_token>
    
    Handles:
    - Send/receive chat messages
    - Typing indicators
    - Read receipts
    """
    
    async def connect(self):
        """Handle WebSocket connection."""
        self.user = await self.get_user_from_token()
        if self.user is None or isinstance(self.user, AnonymousUser):
            await self.close()
        else:
            self.group_name = f"chat_{self.user.id}"
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        """Handle incoming messages."""
        data = json.loads(text_data)
        message_type = data.get('type')
        
        if message_type == 'chat_message':
            await self.handle_chat_message(data)
        elif message_type == 'typing':
            await self.handle_typing(data)
        elif message_type == 'read_receipt':
            await self.handle_read_receipt(data)

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

    async def handle_chat_message(self, data):
        """Handle incoming chat message."""
        from Chat.models import ChatConversation, ChatMessage
        
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
        """Handle typing indicator."""
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
        """Handle read receipt."""
        from Chat.models import ChatMessage
        
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
        """Handle outgoing chat message."""
        await self.send(text_data=json.dumps({
            'type': 'chat_message',
            'message': event['message']
        }))

    async def typing_indicator(self, event):
        """Handle typing indicator broadcast."""
        await self.send(text_data=json.dumps({
            'type': 'typing',
            'user_id': event['user_id'],
            'is_typing': event['is_typing']
        }))

    async def read_receipt(self, event):
        """Handle read receipt broadcast."""
        await self.send(text_data=json.dumps({
            'type': 'read_receipt',
            'message_id': event['message_id']
        }))
