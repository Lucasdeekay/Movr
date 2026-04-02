"""
Tests for Routes app serializers.

This module contains comprehensive tests for RouteSerializer,
ScheduledRouteSerializer, and DaySerializer.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth import get_user_model

from Routes.models import Route, ScheduledRoute, Day
from Routes.serializers import RouteSerializer, ScheduledRouteSerializer, DaySerializer

User = get_user_model()


class DaySerializerTest(TestCase):
    """Test cases for DaySerializer."""

    def setUp(self):
        """Set up test data."""
        self.monday = Day.objects.create(name='Monday', slug='monday', order=1)

    def test_day_serializer_fields(self):
        """Test day serializer includes expected fields."""
        serializer = DaySerializer(self.monday)
        data = serializer.data
        
        self.assertIn('id', data)
        self.assertIn('name', data)
        self.assertIn('slug', data)
        self.assertIn('order', data)

    def test_day_serializer_data(self):
        """Test day serializer data accuracy."""
        serializer = DaySerializer(self.monday)
        data = serializer.data
        
        self.assertEqual(data['name'], 'Monday')
        self.assertEqual(data['slug'], 'monday')
        self.assertEqual(data['order'], 1)

    def test_day_serializer_create(self):
        """Test creating day via serializer."""
        data = {'name': 'Tuesday', 'slug': 'tuesday', 'order': 2}
        serializer = DaySerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        day = serializer.save()
        self.assertEqual(day.name, 'Tuesday')
        self.assertEqual(day.slug, 'tuesday')

    def test_day_serializer_invalid_order(self):
        """Test day serializer validation for invalid order."""
        data = {'name': 'Test', 'slug': 'test', 'order': 'invalid'}
        serializer = DaySerializer(data=data)
        self.assertFalse(serializer.is_valid())


class RouteSerializerTest(TestCase):
    """Test cases for RouteSerializer."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123'
        )

    def test_route_serializer_fields(self):
        """Test route serializer includes expected fields."""
        route = Route.objects.create(
            user=self.user,
            location='Lagos',
            destination='Abuja',
            transportation_mode='car'
        )
        serializer = RouteSerializer(route)
        data = serializer.data
        
        self.assertIn('id', data)
        self.assertIn('user', data)
        self.assertIn('location', data)
        self.assertIn('destination', data)
        self.assertIn('transportation_mode', data)
        self.assertIn('is_live', data)

    def test_route_serializer_create(self):
        """Test creating route via serializer."""
        data = {
            'location': 'Lagos',
            'location_latitude': '6.5244',
            'location_longitude': '3.3792',
            'destination': 'Abuja',
            'destination_latitude': '9.0765',
            'destination_longitude': '7.3986',
            'transportation_mode': 'car',
            'service_type': 'ride',
            'available_seats': 3,
            'price': '5000.00'
        }
        serializer = RouteSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        route = serializer.save(user=self.user)
        self.assertEqual(route.location, 'Lagos')
        self.assertEqual(route.destination, 'Abuja')
        self.assertEqual(route.user, self.user)

    def test_route_serializer_invalid_transportation_mode(self):
        """Test route serializer validation for invalid mode."""
        data = {
            'location': 'Lagos',
            'destination': 'Abuja',
            'transportation_mode': 'invalid_mode'
        }
        serializer = RouteSerializer(data=data)
        self.assertFalse(serializer.is_valid())

    def test_route_serializer_invalid_seats(self):
        """Test route serializer validation for invalid seats."""
        data = {
            'location': 'Lagos',
            'destination': 'Abuja',
            'transportation_mode': 'car',
            'available_seats': -1
        }
        serializer = RouteSerializer(data=data)
        self.assertFalse(serializer.is_valid())

    def test_route_serializer_invalid_price(self):
        """Test route serializer validation for invalid price."""
        data = {
            'location': 'Lagos',
            'destination': 'Abuja',
            'transportation_mode': 'car',
            'price': '-100'
        }
        serializer = RouteSerializer(data=data)
        self.assertFalse(serializer.is_valid())


class ScheduledRouteSerializerTest(TestCase):
    """Test cases for ScheduledRouteSerializer."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123'
        )
        self.monday = Day.objects.create(name='Monday', slug='monday', order=1)

    def test_scheduled_route_serializer_fields(self):
        """Test scheduled route serializer includes expected fields."""
        route = ScheduledRoute.objects.create(
            user=self.user,
            location='Lagos',
            destination='Abuja',
            transportation_mode='car'
        )
        route.days.add(self.monday)
        
        serializer = ScheduledRouteSerializer(route)
        data = serializer.data
        
        self.assertIn('id', data)
        self.assertIn('user', data)
        self.assertIn('location', data)
        self.assertIn('destination', data)
        self.assertIn('days', data)
        self.assertIn('is_active', data)

    def test_scheduled_route_serializer_create(self):
        """Test creating scheduled route via serializer."""
        data = {
            'location': 'Lagos',
            'location_latitude': '6.5244',
            'location_longitude': '3.3792',
            'destination': 'Abuja',
            'destination_latitude': '9.0765',
            'destination_longitude': '7.3986',
            'transportation_mode': 'car',
            'service_type': 'ride',
            'available_seats': 3,
            'price': '5000.00',
            'days': [self.monday.id],
            'is_active': True
        }
        serializer = ScheduledRouteSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        route = serializer.save(user=self.user)
        self.assertEqual(route.location, 'Lagos')
        self.assertTrue(route.is_active)

    def test_scheduled_route_serializer_empty_days(self):
        """Test scheduled route serializer requires days."""
        data = {
            'location': 'Lagos',
            'destination': 'Abuja',
            'transportation_mode': 'car',
            'days': []
        }
        serializer = ScheduledRouteSerializer(data=data)
        self.assertFalse(serializer.is_valid())
