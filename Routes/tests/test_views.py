"""
Tests for Routes app API views.

This module contains comprehensive tests for Routes API endpoints
including CreateRouteView, UserRoutesView, ToggleIsLiveRouteView, etc.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.authtoken.models import Token

from Routes.models import Route, ScheduledRoute, Day

User = get_user_model()


class CreateRouteViewTest(APITestCase):
    """Test cases for CreateRouteView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def test_create_route_success(self):
        """Test creating a route successfully."""
        data = {
            'location': 'Lagos',
            'location_latitude': '6.5244',
            'location_longitude': '3.3792',
            'destination': 'Abuja',
            'destination_latitude': '9.0765',
            'destination_longitude': '7.3986',
            'transportation_mode': 'car',
            'departure_time': '08:00:00',
            'service_type': 'ride',
            'available_seats': 3,
            'price': '5000.00'
        }
        response = self.client.post('/routes/create-route/', data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['location'], 'Lagos')
        self.assertEqual(response.data['destination'], 'Abuja')

    def test_create_route_unauthenticated(self):
        """Test creating route without authentication."""
        self.client.credentials()
        data = {'location': 'Lagos', 'destination': 'Abuja'}
        response = self.client.post('/routes/create-route/', data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_route_invalid_data(self):
        """Test creating route with invalid data."""
        data = {'location': '', 'destination': 'Abuja'}
        response = self.client.post('/routes/create-route/', data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UserRoutesViewTest(APITestCase):
    """Test cases for UserRoutesView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        Route.objects.create(
            user=self.user,
            location='Lagos',
            destination='Abuja',
            transportation_mode='car'
        )

    def test_get_user_routes(self):
        """Test getting user's routes."""
        response = self.client.get('/routes/user-routes/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_get_user_routes_empty(self):
        """Test getting routes when none exist."""
        User.objects.create_user(email='empty@example.com', password='pass123')
        token = Token.objects.get(user__email='empty@example.com')
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        
        response = self.client.get('/routes/user-routes/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)


class ToggleIsLiveRouteViewTest(APITestCase):
    """Test cases for ToggleIsLiveRouteView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        self.route = Route.objects.create(
            user=self.user,
            location='Lagos',
            destination='Abuja',
            transportation_mode='car'
        )

    def test_toggle_route_live(self):
        """Test toggling route live status."""
        response = self.client.post(f'/routes/toggle-is-live/{self.route.id}/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('is_live', response.data)

    def test_toggle_route_not_found(self):
        """Test toggling non-existent route."""
        response = self.client.post('/routes/toggle-is-live/999/')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class GetScheduledRoutesViewTest(APITestCase):
    """Test cases for GetScheduledRoutesView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        self.monday = Day.objects.create(name='Monday', slug='monday', order=1)
        self.scheduled_route = ScheduledRoute.objects.create(
            user=self.user,
            location='Lagos',
            destination='Abuja',
            transportation_mode='car',
            is_active=True
        )
        self.scheduled_route.days.add(self.monday)

    def test_get_scheduled_routes(self):
        """Test getting scheduled routes."""
        response = self.client.get('/routes/scheduled-routes/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)


class GetLiveRoutesCountViewTest(APITestCase):
    """Test cases for GetLiveRoutesCountView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        Route.objects.create(
            user=self.user,
            location='Lagos',
            destination='Abuja',
            transportation_mode='car',
            is_live=True
        )

    def test_get_live_routes_count(self):
        """Test getting live routes count."""
        response = self.client.get('/routes/live-routes-count/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('live_routes_count', response.data)


class DaysListViewTest(APITestCase):
    """Test cases for DaysListView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        Day.objects.create(name='Monday', slug='monday', order=1)
        Day.objects.create(name='Friday', slug='friday', order=5)

    def test_get_days_list(self):
        """Test getting days list."""
        response = self.client.get('/routes/days/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)
