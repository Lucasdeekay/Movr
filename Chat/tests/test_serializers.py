"""
Tests for Chat app serializers.

This module contains tests for ChatConversationSerializer and ChatMessageSerializer.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from Chat.models import ChatConversation, ChatMessage
from Chat.serializers import ChatConversationSerializer, ChatMessageSerializer

User = get_user_model()


class ChatConversationSerializerTest(TestCase):
    """Test cases for ChatConversationSerializer."""

    def setUp(self):
        """Set up test data."""
        self.user1 = User.objects.create_user(
            email='user1@example.com',
            password='testpass123'
        )
        self.user2 = User.objects.create_user(
            email='user2@example.com',
            password='testpass123'
        )
        self.conversation = ChatConversation.objects.create(is_active=True)
        self.conversation.participants.add(self.user1, self.user2)

    def test_serialize_conversation(self):
        """Test serializing a conversation."""
        serializer = ChatConversationSerializer(self.conversation)
        data = serializer.data
        
        self.assertIn('id', data)
        self.assertIn('participants', data)
        self.assertIn('participant_emails', data)
        self.assertIn('is_active', data)
        self.assertEqual(len(data['participant_emails']), 2)
        self.assertIn('user1@example.com', data['participant_emails'])
        self.assertIn('user2@example.com', data['participant_emails'])

    def test_deserialize_conversation(self):
        """Test deserializing a conversation."""
        data = {'is_active': True}
        serializer = ChatConversationSerializer(data=data)
        
        self.assertTrue(serializer.is_valid())

    def test_deserialize_conversation_invalid(self):
        """Test deserializing with invalid data."""
        data = {'is_active': 'not_boolean'}
        serializer = ChatConversationSerializer(data=data)
        
        self.assertFalse(serializer.is_valid())


class ChatMessageSerializerTest(TestCase):
    """Test cases for ChatMessageSerializer."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='sender@example.com',
            password='testpass123'
        )
        self.conversation = ChatConversation.objects.create()
        self.conversation.participants.add(self.user)
        self.message = ChatMessage.objects.create(
            conversation=self.conversation,
            sender=self.user,
            message='Hello world!'
        )

    def test_serialize_message(self):
        """Test serializing a message."""
        serializer = ChatMessageSerializer(self.message)
        data = serializer.data
        
        self.assertIn('id', data)
        self.assertIn('conversation', data)
        self.assertIn('sender', data)
        self.assertIn('sender_email', data)
        self.assertIn('message', data)
        self.assertIn('is_read', data)
        self.assertEqual(data['message'], 'Hello world!')
        self.assertEqual(data['sender_email'], 'sender@example.com')

    def test_deserialize_message(self):
        """Test deserializing a message."""
        data = {
            'conversation': str(self.conversation.id),
            'message': 'New message'
        }
        serializer = ChatMessageSerializer(data=data)
        
        self.assertTrue(serializer.is_valid())

    def test_deserialize_message_invalid(self):
        """Test deserializing with invalid data."""
        data = {
            'conversation': '',
            'message': ''
        }
        serializer = ChatMessageSerializer(data=data)
        
        self.assertFalse(serializer.is_valid())
