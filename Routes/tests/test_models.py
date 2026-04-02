"""
Tests for Routes app models.

This module contains comprehensive tests for Route, ScheduledRoute,
and Day models including creation, validation, and model methods.
"""

from datetime import datetime, time
from decimal import Decimal
from django.test import TestCase
from django.contrib.auth import get_user_model

from Routes.models import Route, ScheduledRoute, Day

User = get_user_model()


class DayModelTest(TestCase):
    """Test cases for Day model."""

    def setUp(self):
        """Set up test data."""
        self.monday = Day.objects.create(name='Monday', slug='monday', order=1)
        self.friday = Day.objects.create(name='Friday', slug='friday', order=5)

    def test_day_creation(self):
        """Test day creation."""
        self.assertEqual(self.monday.name, 'Monday')
        self.assertEqual(self.monday.slug, 'monday')
        self.assertEqual(self.monday.order, 1)

    def test_day_string_representation(self):
        """Test day string representation."""
        self.assertEqual(str(self.monday), 'Monday')

    def test_day_ordering(self):
        """Test days are ordered by order field."""
        days = Day.objects.all()
        self.assertEqual(days[0], self.monday)
        self.assertEqual(days[1], self.friday)

    def test_get_day_by_slug(self):
        """Test getting day by slug."""
        day = Day.get_day_by_slug('monday')
        self.assertEqual(day, self.monday)

        day = Day.get_day_by_slug('nonexistent')
        self.assertIsNone(day)


class RouteModelTest(TestCase):
    """Test cases for Route model."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123',
            first_name='Driver',
            last_name='User'
        )
        self.route = Route.objects.create(
            user=self.user,
            location='Lagos',
            location_latitude=Decimal('6.5244'),
            location_longitude=Decimal('3.3792'),
            destination='Abuja',
            destination_latitude=Decimal('9.0765'),
            destination_longitude=Decimal('7.3986'),
            transportation_mode='car',
            departure_time=time(8, 0),
            service_type='ride',
            available_seats=3,
            price=Decimal('5000.00')
        )

    def test_route_creation(self):
        """Test route creation."""
        self.assertEqual(self.route.user, self.user)
        self.assertEqual(self.route.location, 'Lagos')
        self.assertEqual(self.route.destination, 'Abuja')
        self.assertEqual(self.route.transportation_mode, 'car')
        self.assertFalse(self.route.is_live)

    def test_route_string_representation(self):
        """Test route string representation."""
        expected = f"Lagos to Abuja by {self.user.email}"
        self.assertEqual(str(self.route), expected)

    def test_route_toggle_live(self):
        """Test toggling route live status."""
        self.assertFalse(self.route.is_live)
        
        self.route.is_live = True
        self.route.save()
        
        self.route.refresh_from_db()
        self.assertTrue(self.route.is_live)

    def test_route_available_seats(self):
        """Test available seats field."""
        self.assertEqual(self.route.available_seats, 3)

    def test_route_price(self):
        """Test route price."""
        self.assertEqual(self.route.price, Decimal('5000.00'))

    def test_route_coordinates(self):
        """Test route coordinates."""
        self.assertEqual(self.route.location_latitude, Decimal('6.5244'))
        self.assertEqual(self.route.location_longitude, Decimal('3.3792'))
        self.assertEqual(self.route.destination_latitude, Decimal('9.0765'))
        self.assertEqual(self.route.destination_longitude, Decimal('7.3986'))


class ScheduledRouteModelTest(TestCase):
    """Test cases for ScheduledRoute model."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='driver@example.com',
            password='testpass123'
        )
        self.monday = Day.objects.create(name='Monday', slug='monday', order=1)
        self.friday = Day.objects.create(name='Friday', slug='friday', order=5)
        
        self.scheduled_route = ScheduledRoute.objects.create(
            user=self.user,
            location='Lagos',
            location_latitude=Decimal('6.5244'),
            location_longitude=Decimal('3.3792'),
            destination='Abuja',
            destination_latitude=Decimal('9.0765'),
            destination_longitude=Decimal('7.3986'),
            transportation_mode='car',
            departure_time=time(8, 0),
            service_type='ride',
            available_seats=3,
            price=Decimal('5000.00'),
            is_active=True
        )
        self.scheduled_route.days.add(self.monday, self.friday)

    def test_scheduled_route_creation(self):
        """Test scheduled route creation."""
        self.assertEqual(self.scheduled_route.user, self.user)
        self.assertEqual(self.scheduled_route.location, 'Lagos')
        self.assertTrue(self.scheduled_route.is_active)

    def test_scheduled_route_string_representation(self):
        """Test scheduled route string representation."""
        expected = f"Scheduled: Lagos to Abuja by {self.user.email}"
        self.assertEqual(str(self.scheduled_route), expected)

    def test_scheduled_route_days(self):
        """Test scheduled route days relationship."""
        days = self.scheduled_route.days.all()
        self.assertEqual(days.count(), 2)
        self.assertIn(self.monday, days)
        self.assertIn(self.friday, days)

    def test_scheduled_route_toggle_active(self):
        """Test toggling scheduled route active status."""
        self.assertTrue(self.scheduled_route.is_active)
        
        self.scheduled_route.is_active = False
        self.scheduled_route.save()
        
        self.scheduled_route.refresh_from_db()
        self.assertFalse(self.scheduled_route.is_active)

    def test_get_active_scheduled_routes(self):
        """Test getting active scheduled routes."""
        routes = ScheduledRoute.get_active_scheduled_routes()
        self.assertIn(self.scheduled_route, routes)

        self.scheduled_route.is_active = False
        self.scheduled_route.save()
        
        routes = ScheduledRoute.get_active_scheduled_routes()
        self.assertNotIn(self.scheduled_route, routes)
