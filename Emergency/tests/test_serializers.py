"""
Tests for Emergency app serializers.

This module contains tests for EmergencySOSSerializer.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth import get_user_model
from Emergency.models import EmergencySOS
from Emergency.serializers import EmergencySOSSerializer

User = get_user_model()


class EmergencySOSSerializerTest(TestCase):
    """Test cases for EmergencySOSSerializer."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='user@example.com',
            password='testpass123'
        )
        self.sos = EmergencySOS.objects.create(
            user=self.user,
            latitude=Decimal('6.5244'),
            longitude=Decimal('3.3792'),
            message='Emergency!'
        )

    def test_serialize_sos(self):
        """Test serializing an SOS."""
        serializer = EmergencySOSSerializer(self.sos)
        data = serializer.data
        
        self.assertIn('id', data)
        self.assertIn('user', data)
        self.assertIn('user_email', data)
        self.assertIn('latitude', data)
        self.assertIn('longitude', data)
        self.assertIn('message', data)
        self.assertIn('status', data)
        self.assertEqual(data['user_email'], 'user@example.com')
        self.assertEqual(data['status'], 'pending')

    def test_deserialize_sos(self):
        """Test deserializing an SOS."""
        data = {
            'latitude': '9.0765',
            'longitude': '7.3986',
            'message': 'Help needed'
        }
        serializer = EmergencySOSSerializer(data=data)
        
        self.assertTrue(serializer.is_valid())

    def test_deserialize_sos_invalid(self):
        """Test deserializing with invalid data."""
        data = {'latitude': 'invalid'}
        serializer = EmergencySOSSerializer(data=data)
        
        self.assertFalse(serializer.is_valid())
