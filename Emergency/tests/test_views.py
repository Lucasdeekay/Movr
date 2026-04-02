"""
Tests for Emergency app API views.

This module contains tests for TriggerSOSView, GetSOSAlertsView,
AcknowledgeSOSView, and ResolveSOSView.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.authtoken.models import Token

from Emergency.models import EmergencySOS

User = get_user_model()


class TriggerSOSViewTest(APITestCase):
    """Test cases for TriggerSOSView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='user@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def test_trigger_sos_success(self):
        """Test triggering SOS successfully."""
        data = {
            'latitude': '6.5244',
            'longitude': '3.3792',
            'message': 'Emergency!'
        }
        response = self.client.post('/emergency/trigger/', data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['status'], 'pending')

    def test_trigger_sos_unauthenticated(self):
        """Test triggering SOS without authentication."""
        self.client.credentials()
        data = {'message': 'Emergency!'}
        response = self.client.post('/emergency/trigger/', data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class GetSOSAlertsViewTest(APITestCase):
    """Test cases for GetSOSAlertsView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='user@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        EmergencySOS.objects.create(user=self.user, message='SOS 1')
        EmergencySOS.objects.create(user=self.user, message='SOS 2')

    def test_get_sos_alerts(self):
        """Test getting user's SOS alerts."""
        response = self.client.get('/emergency/alerts/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_get_sos_alerts_admin_sees_all(self):
        """Test admin sees all SOS alerts."""
        admin = User.objects.create_user(
            email='admin@example.com',
            password='admin123',
            is_staff=True
        )
        token = Token.objects.create(user=admin)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        response = self.client.get('/emergency/alerts/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class AcknowledgeSOSViewTest(APITestCase):
    """Test cases for AcknowledgeSOSView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='user@example.com',
            password='testpass123'
        )
        self.sos = EmergencySOS.objects.create(user=self.user)

    def test_acknowledge_sos_admin_only(self):
        """Test only admin can acknowledge SOS."""
        admin = User.objects.create_user(
            email='admin@example.com',
            password='admin123',
            is_staff=True
        )
        token = Token.objects.create(user=admin)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        response = self.client.post(f'/emergency/acknowledge/{self.sos.id}/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.sos.refresh_from_db()
        self.assertEqual(self.sos.status, 'acknowledged')

    def test_acknowledge_sos_non_admin_forbidden(self):
        """Test non-admin cannot acknowledge SOS."""
        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        response = self.client.post(f'/emergency/acknowledge/{self.sos.id}/')
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_acknowledge_sos_not_found(self):
        """Test acknowledging non-existent SOS."""
        admin = User.objects.create_user(
            email='admin@example.com',
            password='admin123',
            is_staff=True
        )
        token = Token.objects.create(user=admin)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        response = self.client.post('/emergency/acknowledge/999/')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class ResolveSOSViewTest(APITestCase):
    """Test cases for ResolveSOSView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='user@example.com',
            password='testpass123'
        )
        self.sos = EmergencySOS.objects.create(user=self.user)

    def test_resolve_sos_admin_only(self):
        """Test only admin can resolve SOS."""
        admin = User.objects.create_user(
            email='admin@example.com',
            password='admin123',
            is_staff=True
        )
        token = Token.objects.create(user=admin)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        response = self.client.post(f'/emergency/resolve/{self.sos.id}/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.sos.refresh_from_db()
        self.assertEqual(self.sos.status, 'resolved')
        self.assertIsNotNone(self.sos.resolved_at)

    def test_resolve_sos_non_admin_forbidden(self):
        """Test non-admin cannot resolve SOS."""
        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        response = self.client.post(f'/emergency/resolve/{self.sos.id}/')
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
