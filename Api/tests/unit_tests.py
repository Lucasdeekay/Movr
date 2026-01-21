"""
Comprehensive unit tests for Api views.

This module provides thorough testing for all API views to ensure
they work correctly with various input scenarios, edge cases, and error conditions.
"""

import pytest
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token
from unittest.mock import patch, MagicMock

from Api.models import (
    CustomUser, KYC, Vehicle, Subscription, SubscriptionPlan, OTP,
    Route, ScheduledRoute, Day, Package, Bid, QRCode, PackageOffer,
    SocialMediaLink
)
from PIL import Image
from io import BytesIO
from django.core.files.uploadedfile import SimpleUploadedFile


class BaseTestCase(TestCase):
    """Base test case with common setup methods."""
    
    def setUp(self):
        self.client = APIClient()
        self.user = None
        self.token = None
        
    def create_user(self, email="testuser@example.com", is_verified=True):
        """Create a test user and return the user with token."""
        user = get_user_model().objects.create_user(
            email=email,
            password="password123",
            is_email_verified=is_verified
        )
        token = Token.objects.create(user=user)
        self.user = user
        self.token = token
        return user, token
    
    def authenticate(self):
        """Authenticate the test client."""
        if self.token:
            self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
    
    def tearDown(self):
        """Clean up after each test."""
        self.client.credentials()


class AuthViewsTest(BaseTestCase):
    """Test authentication-related views."""
    
    def test_register_user_success(self):
        """Test successful user registration."""
        url = reverse('register')
        data = {
            "email": "newuser@example.com",
            "password": "password123",
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('email', response.data)
        
        # Verify user was created
        user = CustomUser.objects.filter(email=data['email']).first()
        self.assertIsNotNone(user)
        self.assertTrue(user.check_password(data['password']))
        
        # Verify associated objects were created
        self.assertTrue(KYC.objects.filter(user=user).exists())
        self.assertTrue(Vehicle.objects.filter(user=user).exists())
        self.assertTrue(Subscription.objects.filter(user=user).exists())
        self.assertTrue(OTP.objects.filter(user=user).exists())
    
    def test_register_user_invalid_data(self):
        """Test registration with invalid data."""
        url = reverse('register')
        test_cases = [
            # Missing required fields
            ({}, 400),
            ({"email": ""}, 400),
            ({"password": ""}, 400),
            # Invalid email format
            ({"email": "invalid-email", "password": "password123"}, 400),
            # Existing email (should be handled by serializer)
        ]
        
        for data, expected_status in test_cases:
            with self.subTest(data=data):
                response = self.client.post(url, data, format='json')
                self.assertEqual(response.status_code, expected_status)

    def test_verify_otp_success(self):
        """Test successful OTP verification."""
        user, token = self.create_user(is_verified=False)
        otp = OTP.objects.create(user=user)
        
        url = reverse('verify-otp')
        data = {"email": user.email, "code": otp.code}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertTrue(user.is_email_verified)
    
    def test_login_success(self):
        """Test successful login."""
        user, token = self.create_user()
        
        url = reverse('login')
        data = {"email": user.email, "password": "password123"}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        url = reverse('login')
        test_cases = [
            ({"email": "wrong@example.com", "password": "password123"}, 400),
            ({"email": "testuser@example.com", "password": "wrongpassword"}, 400),
        ]
        
        for data, expected_status in test_cases:
            with self.subTest(data=data):
                response = self.client.post(url, data, format='json')
                self.assertEqual(response.status_code, expected_status)

    def test_logout_success(self):
        """Test successful logout."""
        user, token = self.create_user()
        self.authenticate()
        
        url = reverse('logout')
        response = self.client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify token was deleted
        with self.assertRaises(Exception):
            Token.objects.get(user=user)


class ProfileViewsTest(BaseTestCase):
    """Test profile-related views."""
    
    def test_upload_profile_image_success(self):
        """Test successful profile image upload."""
        user, token = self.create_user()
        self.authenticate()
        
        url = reverse('upload-profile-image')
        
        # Create test image
        image = Image.new('RGB', (200, 200), 'blue')
        image_file = BytesIO()
        image.save(image_file, 'jpeg')
        image_file.seek(0)
        
        response = self.client.post(
            url,
            {'profile_picture': SimpleUploadedFile(
                'test_image.jpg',
                image_file.getvalue(),
                content_type='image/jpeg'
            )},
            format='multipart'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        user.refresh_from_db()
        self.assertIsNotNone(user.profile_picture)
    
    def test_upload_profile_image_validation(self):
        """Test profile image upload validation."""
        user, token = self.create_user()
        self.authenticate()
        
        url = reverse('upload-profile-image')
        
        # Test cases for validation
        test_cases = [
            # Missing file
            ({}, 400, 'Profile picture is required.'),
            # Invalid file type
            ({
                'profile_picture': SimpleUploadedFile(
                    'test_file.txt',
                    b'Not an image',
                    content_type='text/plain'
                )
            }, 400, 'Profile picture must be a valid image file.'),
            # File too large (simulate large file)
            ({
                'profile_picture': SimpleUploadedFile(
                    'large_file.jpg',
                    b'x' * (6 * 1024 * 1024),  # 6MB
                    content_type='image/jpeg'
                )
            }, 400, 'Profile picture size must be under 5MB.'),
        ]
        
        for data, expected_status, expected_error in test_cases:
            with self.subTest(data=data):
                response = self.client.post(url, data, format='multipart')
                self.assertEqual(response.status_code, expected_status)
                self.assertEqual(response.data['error'], expected_error)


class RouteViewsTest(BaseTestCase):
    """Test route-related views."""
    
    def test_create_route_success(self):
        """Test successful route creation."""
        user, token = self.create_user()
        self.authenticate()
        
        url = reverse('create-route')
        data = {
            "location": "Location A",
            "location_latitude": 40.712776,
            "location_longitude": -74.005974,
            "destination": "Location B",
            "destination_latitude": 34.052235,
            "destination_longitude": -118.243683,
            "transportation_mode": "car",
            "departure_time": timezone.now().isoformat(),
            "service_type": "ride",
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('message', response.data)
        self.assertIn('route', response.data)
        
        # Verify route was created
        route = Route.objects.filter(user=user, location=data['location']).first()
        self.assertIsNotNone(route)
        self.assertEqual(route.location, data['location'])
        self.assertEqual(route.destination, data['destination'])
    
    def test_create_route_with_null_stop_location(self):
        """Test route creation with null stop location values."""
        user, token = self.create_user()
        self.authenticate()
        
        url = reverse('create-route')
        data = {
            "location": "Location A",
            "location_latitude": 40.712776,
            "location_longitude": -74.005974,
            "destination": "Location B",
            "destination_latitude": 34.052235,
            "destination_longitude": -118.243683,
            "stop_location": "",
            "stop_location_latitude": None,
            "stop_location_longitude": None,
            "transportation_mode": "car",
            "departure_time": timezone.now().isoformat(),
            "service_type": "ride",
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify route was created with null stop location values
        route = Route.objects.filter(user=user, location=data['location']).first()
        self.assertIsNotNone(route)
        self.assertEqual(route.stop_location, "")
        self.assertIsNone(route.stop_location_latitude)
        self.assertIsNone(route.stop_location_longitude)
    
    def test_create_route_validation(self):
        """Test route creation validation."""
        user, token = self.create_user()
        self.authenticate()
        
        url = reverse('create-route')
        
        # Test cases for validation
        test_cases = [
            # Missing required fields
            ({"transportation_mode": "car"}, 400),
            ({"destination": "Location B"}, 400),
            ({"location": "Location A"}, 400),
        ]
        
        for data, expected_status in test_cases:
            with self.subTest(data=data):
                response = self.client.post(url, data, format='json')
                self.assertEqual(response.status_code, expected_status)


class PackageViewsTest(BaseTestCase):
    """Test package-related views."""
    
    def test_submit_package_success(self):
        """Test successful package submission."""
        user, token = self.create_user()
        self.authenticate()
        
        url = reverse('submit-package')
        data = {
            "location": "Origin City",
            "location_latitude": 40.712776,
            "location_longitude": -74.005974,
            "destination": "Destination City",
            "destination_latitude": 34.052235,
            "destination_longitude": -118.243683,
            "package_type": "Delivery",
            "item_description": "Books and gadgets",
            "item_weight": "medium",
            "receiver_name": "John Doe",
            "receiver_phone_number": "1234567890",
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('id', response.data)
        
        # Verify package was created
        package = Package.objects.filter(user=user, location=data['location']).first()
        self.assertIsNotNone(package)
        self.assertEqual(package.location, data['location'])
        self.assertEqual(package.destination, data['destination'])
    
    def test_place_bid_success(self):
        """Test successful bid placement."""
        user, token = self.create_user()
        self.authenticate()
        
        # Create a package first
        package = Package.objects.create(
            user=user,
            location="Origin City",
            destination="Destination City",
            package_type="Delivery"
        )
        
        url = reverse('place-bid', kwargs={'package_id': str(package.id)})
        data = {"price": "100.00"}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('message', response.data)
        self.assertEqual(response.data['message'], 'Bid placed successfully.')
        
        # Verify bid was created
        bid = Bid.objects.filter(package=package, mover=user).first()
        self.assertIsNotNone(bid)
        self.assertEqual(float(bid.price), 100.00)


class EdgeCaseTest(BaseTestCase):
    """Test edge cases and error scenarios."""
    
    def test_unauthenticated_access(self):
        """Test that unauthenticated access is blocked."""
        protected_urls = [
            ('create-route', 'POST'),
            ('upload-profile-image', 'POST'),
            ('submit-package', 'POST'),
            ('user-routes', 'GET'),
        ]
        
        for url_name, method in protected_urls:
            with self.subTest(url_name=url_name, method=method):
                url = reverse(url_name)
                if method == 'POST':
                    response = self.client.post(url, {}, format='json')
                else:
                    response = self.client.get(url)
                
                self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_invalid_uuid_handling(self):
        """Test handling of invalid UUID formats."""
        user, token = self.create_user()
        self.authenticate()
        
        url = reverse('place-bid', kwargs={'package_id': 'invalid-uuid-format'})
        data = {"price": "100.00"}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class IntegrationTest(BaseTestCase):
    """Test integration scenarios between multiple views."""
    
    def test_user_flow_complete(self):
        """Test complete user flow from registration to route creation."""
        # 1. Register user with unique email to avoid rate limiting
        import time
        unique_email = f"integration{int(time.time())}@example.com"
        register_url = reverse('register')
        register_data = {
            "email": unique_email,
            "password": "password123",
        }
        
        response = self.client.post(register_url, register_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # 2. Verify OTP was created
        user = CustomUser.objects.get(email=register_data['email'])
        otp = OTP.objects.get(user=user)
        
        # 3. Verify OTP
        verify_url = reverse('verify-otp')
        verify_data = {"email": user.email, "code": otp.code}
        
        response = self.client.post(verify_url, verify_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # 4. Login
        login_url = reverse('login')
        login_data = {"email": user.email, "password": "password123"}
        
        response = self.client.post(login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        token = response.data['token']['key']
        
        # 5. Create route
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        route_url = reverse('create-route')
        route_data = {
            "location": "Home",
            "destination": "Work",
            "transportation_mode": "car",
            "departure_time": timezone.now().isoformat(),
            "service_type": "ride",
        }
        
        response = self.client.post(route_url, route_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


if __name__ == '__main__':
    pytest.main([__file__])