"""
Tests for Chat app API views.

This module contains tests for SendChatMessageView, GetConversationMessagesView,
GetUserConversationsView, and CreateConversationView.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.authtoken.models import Token

from Chat.models import ChatConversation, ChatMessage

User = get_user_model()


class SendChatMessageViewTest(APITestCase):
    """Test cases for SendChatMessageView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='sender@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        self.conversation = ChatConversation.objects.create()
        self.conversation.participants.add(self.user)

    def test_send_message_success(self):
        """Test sending a message successfully."""
        data = {
            'conversation': str(self.conversation.id),
            'message': 'Hello, world!'
        }
        response = self.client.post('/chat/send/', data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['message'], 'Hello, world!')

    def test_send_message_not_participant(self):
        """Test sending message to conversation user is not part of."""
        other_user = User.objects.create_user(
            email='other@example.com',
            password='pass123'
        )
        conversation = ChatConversation.objects.create()
        conversation.participants.add(other_user)
        
        data = {
            'conversation': str(conversation.id),
            'message': 'Hello'
        }
        response = self.client.post('/chat/send/', data)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_send_message_unauthenticated(self):
        """Test sending message without authentication."""
        self.client.credentials()
        data = {
            'conversation': str(self.conversation.id),
            'message': 'Hello'
        }
        response = self.client.post('/chat/send/', data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class GetConversationMessagesViewTest(APITestCase):
    """Test cases for GetConversationMessagesView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='user@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        self.conversation = ChatConversation.objects.create()
        self.conversation.participants.add(self.user)
        
        ChatMessage.objects.create(
            conversation=self.conversation,
            sender=self.user,
            message='First message'
        )

    def test_get_conversation_messages(self):
        """Test getting messages for a conversation."""
        response = self.client.get(f'/chat/{self.conversation.id}/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_get_conversation_messages_not_participant(self):
        """Test getting messages when not a participant."""
        other_user = User.objects.create_user(
            email='other@example.com',
            password='pass123'
        )
        conversation = ChatConversation.objects.create()
        conversation.participants.add(other_user)
        
        response = self.client.get(f'/chat/{conversation.id}/')
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_get_conversation_not_found(self):
        """Test getting messages for non-existent conversation."""
        response = self.client.get('/chat/999/')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class GetUserConversationsViewTest(APITestCase):
    """Test cases for GetUserConversationsView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='user@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        self.conversation = ChatConversation.objects.create(is_active=True)
        self.conversation.participants.add(self.user)

    def test_get_user_conversations(self):
        """Test getting user's conversations."""
        response = self.client.get('/chat/conversations/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_get_user_conversations_empty(self):
        """Test getting conversations when none exist."""
        new_user = User.objects.create_user(
            email='new@example.com',
            password='pass123'
        )
        token = Token.objects.create(user=new_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        response = self.client.get('/chat/conversations/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)


class CreateConversationViewTest(APITestCase):
    """Test cases for CreateConversationView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='user@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        self.other_user = User.objects.create_user(
            email='other@example.com',
            password='pass123'
        )

    def test_create_conversation_success(self):
        """Test creating a conversation."""
        data = {
            'participants': [self.other_user.id],
            'is_active': True
        }
        response = self.client.post('/chat/create/', data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('participants', response.data)

    def test_create_conversation_invalid(self):
        """Test creating conversation with invalid data."""
        data = {'is_active': 'invalid'}
        response = self.client.post('/chat/create/', data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
