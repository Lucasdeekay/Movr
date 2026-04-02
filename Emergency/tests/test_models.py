"""
Tests for Emergency app models.

This module contains tests for EmergencySOS model.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth import get_user_model
from Emergency.models import EmergencySOS

User = get_user_model()


class EmergencySOSModelTest(TestCase):
    """Test cases for EmergencySOS model."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='user@example.com',
            password='testpass123'
        )

    def test_create_sos(self):
        """Test creating an SOS alert."""
        sos = EmergencySOS.objects.create(
            user=self.user,
            latitude=Decimal('6.5244'),
            longitude=Decimal('3.3792'),
            message='Emergency!'
        )
        
        self.assertEqual(sos.user, self.user)
        self.assertEqual(sos.status, 'pending')
        self.assertIsNotNone(sos.id)

    def test_sos_str(self):
        """Test string representation."""
        sos = EmergencySOS.objects.create(user=self.user, status='pending')
        self.assertIn('user@example.com', str(sos))
        self.assertIn('pending', str(sos))

    def test_sos_status_choices(self):
        """Test SOS status choices."""
        sos = EmergencySOS.objects.create(user=self.user)
        
        sos.status = 'acknowledged'
        sos.save()
        
        sos.refresh_from_db()
        self.assertEqual(sos.status, 'acknowledged')
        
        sos.status = 'resolved'
        sos.save()
        
        sos.refresh_from_db()
        self.assertEqual(sos.status, 'resolved')

    def test_sos_with_trip(self):
        """Test SOS linked to a trip."""
        from Packages.models import PackageOffer, Package
        
        package = Package.objects.create(
            owner=self.user,
            pickup_location='Lagos',
            pickup_latitude='6.5244',
            pickup_longitude='3.3792',
            destination='Abuja',
            destination_latitude='9.0765',
            destination_longitude='7.3986',
            weight_kg=10,
            description='Test package'
        )
        mover = User.objects.create_user(email='mover@example.com', password='pass123')
        offer = PackageOffer.objects.create(
            package=package,
            mover=mover,
            agreed_price=5000,
            status='accepted'
        )
        
        sos = EmergencySOS.objects.create(user=self.user, trip=offer)
        self.assertEqual(sos.trip, offer)

    def test_sos_ordering(self):
        """Test SOS ordering by created_at."""
        sos1 = EmergencySOS.objects.create(user=self.user)
        sos2 = EmergencySOS.objects.create(user=self.user)
        
        sos_list = list(EmergencySOS.objects.all())
        self.assertEqual(sos_list[0], sos2)
        self.assertEqual(sos_list[1], sos1)
