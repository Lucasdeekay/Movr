"""
Tests for Chat app models.

This module contains tests for ChatConversation and ChatMessage models.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from Chat.models import ChatConversation, ChatMessage

User = get_user_model()


class ChatConversationModelTest(TestCase):
    """Test cases for ChatConversation model."""

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

    def test_create_conversation(self):
        """Test creating a chat conversation."""
        conversation = ChatConversation.objects.create(is_active=True)
        conversation.participants.add(self.user1, self.user2)
        
        self.assertEqual(conversation.participants.count(), 2)
        self.assertTrue(conversation.is_active)
        self.assertIsNotNone(conversation.id)

    def test_conversation_str(self):
        """Test string representation."""
        conversation = ChatConversation.objects.create()
        self.assertIn('Conversation', str(conversation))

    def test_conversation_with_trip(self):
        """Test conversation linked to a trip."""
        from Packages.models import PackageOffer, Package, CustomUser
        from django.utils import timezone
        
        user = User.objects.create_user(email='owner@example.com', password='pass123')
        package = Package.objects.create(
            owner=user,
            pickup_location='Lagos',
            pickup_latitude='6.5244',
            pickup_longitude='3.3792',
            destination='Abuja',
            destination_latitude='9.0765',
            destination_longitude='7.3986',
            weight_kg=10,
            description='Test package'
        )
        offer = PackageOffer.objects.create(
            package=package,
            mover=user,
            agreed_price=5000,
            status='accepted'
        )
        
        conversation = ChatConversation.objects.create(trip=offer)
        conversation.participants.add(self.user1)
        
        self.assertEqual(conversation.trip, offer)


class ChatMessageModelTest(TestCase):
    """Test cases for ChatMessage model."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='sender@example.com',
            password='testpass123'
        )
        self.conversation = ChatConversation.objects.create()
        self.conversation.participants.add(self.user)

    def test_create_message(self):
        """Test creating a chat message."""
        message = ChatMessage.objects.create(
            conversation=self.conversation,
            sender=self.user,
            message='Hello, world!'
        )
        
        self.assertEqual(message.message, 'Hello, world!')
        self.assertFalse(message.is_read)
        self.assertIsNotNone(message.id)

    def test_message_str(self):
        """Test string representation."""
        message = ChatMessage.objects.create(
            conversation=self.conversation,
            sender=self.user,
            message='Test message'
        )
        self.assertIn('sender@example.com', str(message))

    def test_message_ordering(self):
        """Test messages are ordered by created_at."""
        message1 = ChatMessage.objects.create(
            conversation=self.conversation,
            sender=self.user,
            message='First message'
        )
        message2 = ChatMessage.objects.create(
            conversation=self.conversation,
            sender=self.user,
            message='Second message'
        )
        
        messages = list(self.conversation.messages.all())
        self.assertEqual(messages[0], message1)
        self.assertEqual(messages[1], message2)

    def test_message_mark_as_read(self):
        """Test marking message as read."""
        from django.utils import timezone
        message = ChatMessage.objects.create(
            conversation=self.conversation,
            sender=self.user,
            message='Test'
        )
        message.is_read = True
        message.read_at = timezone.now()
        message.save()
        
        message.refresh_from_db()
        self.assertTrue(message.is_read)
        self.assertIsNotNone(message.read_at)
