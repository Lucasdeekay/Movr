"""
Tests for Packages app serializers.

This module contains comprehensive tests for PackageSerializer,
BidSerializer, and PackageOfferSerializer.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth import get_user_model

from Packages.models import Package, Bid, PackageOffer
from Packages.serializers import PackageSerializer, BidSerializer, PackageOfferSerializer

User = get_user_model()


class PackageSerializerTest(TestCase):
    """Test cases for PackageSerializer."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(email='sender@example.com', password='pass')
        self.package = Package.objects.create(
            user=self.user,
            location='Lagos',
            destination='Abuja',
            package_type='Delivery',
            item_description='Electronics',
            item_weight='medium',
            receiver_name='John Doe',
            receiver_phone_number='+2348012345678'
        )

    def test_package_serializer_fields(self):
        """Test package serializer includes expected fields."""
        serializer = PackageSerializer(self.package)
        data = serializer.data
        
        self.assertIn('id', data)
        self.assertIn('location', data)
        self.assertIn('destination', data)
        self.assertIn('status', data)

    def test_package_serializer_create(self):
        """Test creating package via serializer."""
        data = {
            'location': 'Lagos',
            'destination': 'Abuja',
            'package_type': 'Delivery',
            'item_description': 'Books',
            'item_weight': 'light',
            'receiver_name': 'Jane Doe',
            'receiver_phone_number': '+2348012345678'
        }
        serializer = PackageSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        package = serializer.save(user=self.user)
        self.assertEqual(package.location, 'Lagos')


class BidSerializerTest(TestCase):
    """Test cases for BidSerializer."""

    def setUp(self):
        """Set up test data."""
        self.sender = User.objects.create_user(email='sender@example.com', password='pass')
        self.mover = User.objects.create_user(email='mover@example.com', password='pass')
        
        self.package = Package.objects.create(
            user=self.sender,
            location='Lagos',
            destination='Abuja',
            package_type='Delivery'
        )
        self.bid = Bid.objects.create(
            package=self.package,
            bidder=self.mover,
            amount=Decimal('3000.00')
        )

    def test_bid_serializer_fields(self):
        """Test bid serializer includes expected fields."""
        serializer = BidSerializer(self.bid)
        data = serializer.data
        
        self.assertIn('id', data)
        self.assertIn('amount', data)
        self.assertIn('is_accepted', data)

    def test_bid_serializer_create(self):
        """Test creating bid via serializer."""
        data = {
            'package': self.package.id,
            'amount': '2500.00',
            'message': 'Quick delivery'
        }
        serializer = BidSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        bid = serializer.save(bidder=self.mover)
        self.assertEqual(bid.amount, Decimal('2500.00'))


class PackageOfferSerializerTest(TestCase):
    """Test cases for PackageOfferSerializer."""

    def setUp(self):
        """Set up test data."""
        self.sender = User.objects.create_user(email='sender@example.com', password='pass')
        self.mover = User.objects.create_user(email='mover@example.com', password='pass')
        
        self.package = Package.objects.create(
            user=self.sender,
            location='Lagos',
            destination='Abuja'
        )
        self.bid = Bid.objects.create(
            package=self.package,
            bidder=self.mover,
            amount=Decimal('3000.00')
        )
        self.offer = PackageOffer.objects.create(
            package=self.package,
            bid=self.bid,
            driver=self.mover,
            agreed_amount=Decimal('3000.00')
        )

    def test_package_offer_serializer_fields(self):
        """Test package offer serializer includes expected fields."""
        serializer = PackageOfferSerializer(self.offer)
        data = serializer.data
        
        self.assertIn('id', data)
        self.assertIn('picked_up', data)
        self.assertIn('delivered', data)
        self.assertIn('agreed_amount', data)
