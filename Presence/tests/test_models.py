"""
Tests for Presence app models.

This module contains tests for UserPresence model.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth import get_user_model
from Presence.models import UserPresence

User = get_user_model()


class UserPresenceModelTest(TestCase):
    """Test cases for UserPresence model."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123'
        )

    def test_create_presence(self):
        """Test creating user presence."""
        presence = UserPresence.objects.create(
            user=self.user,
            is_online=True
        )
        
        self.assertEqual(presence.user, self.user)
        self.assertTrue(presence.is_online)
        self.assertIsNotNone(presence.id)

    def test_presence_str(self):
        """Test string representation."""
        presence = UserPresence.objects.create(user=self.user, is_online=True)
        self.assertIn('driver@example.com', str(presence))
        self.assertIn('online', str(presence))

    def test_presence_offline(self):
        """Test presence when user is offline."""
        presence = UserPresence.objects.create(user=self.user, is_online=False)
        self.assertFalse(presence.is_online)

    def test_presence_with_location(self):
        """Test presence with location coordinates."""
        presence = UserPresence.objects.create(
            user=self.user,
            is_online=True,
            current_latitude=Decimal('6.5244'),
            current_longitude=Decimal('3.3792')
        )
        
        self.assertEqual(presence.current_latitude, Decimal('6.5244'))
        self.assertEqual(presence.current_longitude, Decimal('3.3792'))

    def test_unique_presence_per_user(self):
        """Test that each user can only have one presence."""
        UserPresence.objects.create(user=self.user, is_online=True)
        
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            UserPresence.objects.create(user=self.user, is_online=False)
