"""
Tests for Packages app API views.

This module contains comprehensive tests for Packages API endpoints.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.authtoken.models import Token

from Packages.models import Package, Bid, PackageOffer

User = get_user_model()


class PackageSubmissionViewTest(APITestCase):
    """Test cases for PackageSubmissionView."""

    def setUp(self):
        self.user = User.objects.create_user(email='sender@example.com', password='pass')
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def test_submit_package_success(self):
        data = {
            'location': 'Lagos',
            'destination': 'Abuja',
            'package_type': 'Delivery',
            'item_description': 'Electronics',
            'item_weight': 'medium',
            'receiver_name': 'John Doe',
            'receiver_phone_number': '+2348012345678',
            'range_radius': '10.00'
        }
        response = self.client.post('/packages/submit-package/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_submit_package_invalid(self):
        data = {'location': ''}
        response = self.client.post('/packages/submit-package/', data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class PlaceBidViewTest(APITestCase):
    """Test cases for PlaceBidView."""

    def setUp(self):
        self.sender = User.objects.create_user(email='sender@example.com', password='pass')
        self.mover = User.objects.create_user(email='mover@example.com', password='pass')
        self.token = Token.objects.create(user=self.mover)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        self.package = Package.objects.create(
            user=self.sender,
            location='Lagos',
            destination='Abuja',
            package_type='Delivery'
        )

    def test_place_bid_success(self):
        data = {'amount': '3000.00', 'message': 'I can deliver'}
        response = self.client.post(f'/packages/place-bid/{self.package.id}/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_place_bid_package_not_found(self):
        response = self.client.post('/packages/place-bid/999/', {'amount': '100'})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class GetAllPackageOffersViewTest(APITestCase):
    """Test cases for GetAllPackageOffersView."""

    def setUp(self):
        self.user = User.objects.create_user(email='user@example.com', password='pass')
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def test_get_package_offers(self):
        response = self.client.get('/packages/package-offers/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class PickedUpPackageOffersViewTest(APITestCase):
    """Test cases for PickedUpPackageOffersView."""

    def setUp(self):
        self.user = User.objects.create_user(email='user@example.com', password='pass')
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def test_get_picked_up_offers(self):
        response = self.client.get('/packages/offers/picked-up/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class ScheduledPackageOffersViewTest(APITestCase):
    """Test cases for ScheduledPackageOffersView."""

    def setUp(self):
        self.user = User.objects.create_user(email='user@example.com', password='pass')
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def test_get_scheduled_offers(self):
        response = self.client.get('/packages/offers/scheduled/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
