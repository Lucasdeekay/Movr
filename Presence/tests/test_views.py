"""
Tests for Presence app API views.

This module contains tests for UpdatePresenceView, GetOnlineUsersView, and GetUserLocationView.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.authtoken.models import Token

from Presence.models import UserPresence

User = get_user_model()


class UpdatePresenceViewTest(APITestCase):
    """Test cases for UpdatePresenceView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def test_update_presence_success(self):
        """Test updating presence successfully."""
        data = {
            'is_online': True,
            'current_latitude': '6.5244',
            'current_longitude': '3.3792'
        }
        response = self.client.post('/presence/update/', data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['is_online'])

    def test_update_presence_partial(self):
        """Test partial update of presence."""
        UserPresence.objects.create(user=self.user, is_online=True)
        
        data = {'is_online': False}
        response = self.client.post('/presence/update/', data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['is_online'])

    def test_update_presence_unauthenticated(self):
        """Test updating presence without authentication."""
        self.client.credentials()
        data = {'is_online': True}
        response = self.client.post('/presence/update/', data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class GetOnlineUsersViewTest(APITestCase):
    """Test cases for GetOnlineUsersView."""

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
        self.token = Token.objects.create(user=self.user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        UserPresence.objects.create(user=self.user1, is_online=True)
        UserPresence.objects.create(user=self.user2, is_online=False)

    def test_get_online_users(self):
        """Test getting online users."""
        response = self.client.get('/presence/online/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_get_online_users_empty(self):
        """Test getting online users when none."""
        new_user = User.objects.create_user(
            email='new@example.com',
            password='pass123'
        )
        token = Token.objects.create(user=new_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        response = self.client.get('/presence/online/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)


class GetUserLocationViewTest(APITestCase):
    """Test cases for GetUserLocationView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        self.presence = UserPresence.objects.create(
            user=self.user,
            is_online=True,
            current_latitude=Decimal('6.5244'),
            current_longitude=Decimal('3.3792')
        )

    def test_get_user_location(self):
        """Test getting user location."""
        response = self.client.get(f'/presence/user/{self.user.id}/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('current_latitude', response.data)

    def test_get_user_location_not_found(self):
        """Test getting location for non-existent user."""
        response = self.client.get('/presence/user/999/')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
