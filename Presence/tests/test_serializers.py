"""
Tests for Presence app serializers.

This module contains tests for UserPresenceSerializer.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth import get_user_model
from Presence.models import UserPresence
from Presence.serializers import UserPresenceSerializer

User = get_user_model()


class UserPresenceSerializerTest(TestCase):
    """Test cases for UserPresenceSerializer."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123'
        )
        self.presence = UserPresence.objects.create(
            user=self.user,
            is_online=True,
            current_latitude=Decimal('6.5244'),
            current_longitude=Decimal('3.3792')
        )

    def test_serialize_presence(self):
        """Test serializing presence."""
        serializer = UserPresenceSerializer(self.presence)
        data = serializer.data
        
        self.assertIn('id', data)
        self.assertIn('user', data)
        self.assertIn('user_email', data)
        self.assertIn('is_online', data)
        self.assertIn('current_latitude', data)
        self.assertIn('current_longitude', data)
        self.assertEqual(data['user_email'], 'driver@example.com')
        self.assertTrue(data['is_online'])

    def test_deserialize_presence(self):
        """Test deserializing presence."""
        data = {
            'is_online': False,
            'current_latitude': '9.0765',
            'current_longitude': '7.3986'
        }
        serializer = UserPresenceSerializer(self.presence, data=data, partial=True)
        
        self.assertTrue(serializer.is_valid())

    def test_deserialize_presence_invalid(self):
        """Test deserializing with invalid data."""
        data = {'is_online': 'not_boolean'}
        serializer = UserPresenceSerializer(self.presence, data=data, partial=True)
        
        self.assertFalse(serializer.is_valid())
