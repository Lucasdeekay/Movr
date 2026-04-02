"""
Tests for Packages app models.

This module contains comprehensive tests for Package, Bid, PackageOffer,
and QRCode models.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth import get_user_model

from Packages.models import Package, Bid, PackageOffer, QRCode

User = get_user_model()


class PackageModelTest(TestCase):
    """Test cases for Package model."""

    def setUp(self):
        """Set up test data."""
        self.sender = User.objects.create_user(
            email='sender@example.com',
            password='testpass123'
        )
        self.package = Package.objects.create(
            user=self.sender,
            location='Lagos',
            destination='Abuja',
            package_type='Delivery',
            item_description='Electronics',
            item_weight='medium',
            receiver_name='John Doe',
            receiver_phone_number='+2348012345678',
            range_radius=Decimal('10.00')
        )

    def test_package_creation(self):
        """Test package creation."""
        self.assertEqual(self.package.user, self.sender)
        self.assertEqual(self.package.location, 'Lagos')
        self.assertEqual(self.package.destination, 'Abuja')
        self.assertEqual(self.package.status, 'pending')

    def test_package_string_representation(self):
        """Test package string representation."""
        expected = f"Package from {self.sender.email} to John Doe"
        self.assertEqual(str(self.package), expected)

    def test_package_status_default(self):
        """Test package default status is pending."""
        self.assertEqual(self.package.status, 'pending')

    def test_package_update_status(self):
        """Test updating package status."""
        self.package.status = 'accepted'
        self.package.save()
        self.package.refresh_from_db()
        self.assertEqual(self.package.status, 'accepted')


class BidModelTest(TestCase):
    """Test cases for Bid model."""

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
            amount=Decimal('3000.00'),
            message='I can deliver this package'
        )

    def test_bid_creation(self):
        """Test bid creation."""
        self.assertEqual(self.bid.package, self.package)
        self.assertEqual(self.bid.bidder, self.mover)
        self.assertEqual(self.bid.amount, Decimal('3000.00'))
        self.assertFalse(self.bid.is_accepted)

    def test_bid_string_representation(self):
        """Test bid string representation."""
        expected = f"Bid of ₦3000.00 by mover@example.com on Package"
        self.assertEqual(str(self.bid), expected)

    def test_bid_accept(self):
        """Test accepting a bid."""
        self.bid.is_accepted = True
        self.bid.save()
        self.assertTrue(self.bid.is_accepted)


class PackageOfferModelTest(TestCase):
    """Test cases for PackageOffer model."""

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
        self.offer = PackageOffer.objects.create(
            package=self.package,
            bid=self.bid,
            driver=self.mover,
            agreed_amount=Decimal('3000.00')
        )

    def test_package_offer_creation(self):
        """Test package offer creation."""
        self.assertEqual(self.offer.package, self.package)
        self.assertEqual(self.offer.driver, self.mover)
        self.assertEqual(self.offer.agreed_amount, Decimal('3000.00'))
        self.assertFalse(self.offer.picked_up)
        self.assertFalse(self.offer.delivered)

    def test_package_offer_string_representation(self):
        """Test package offer string representation."""
        expected = f"PackageOffer for Package by mover@example.com"
        self.assertEqual(str(self.offer), expected)

    def test_package_offer_pickup(self):
        """Test marking package as picked up."""
        self.offer.picked_up = True
        self.offer.save()
        self.assertTrue(self.offer.picked_up)

    def test_package_offer_delivery(self):
        """Test marking package as delivered."""
        self.offer.picked_up = True
        self.offer.delivered = True
        self.offer.save()
        self.assertTrue(self.offer.delivered)


class QRCodeModelTest(TestCase):
    """Test cases for QRCode model."""

    def setUp(self):
        """Set up test data."""
        self.sender = User.objects.create_user(email='sender@example.com', password='pass')
        
        self.package = Package.objects.create(
            user=self.sender,
            location='Lagos',
            destination='Abuja',
            package_type='Delivery'
        )
        self.qr = QRCode.objects.create(
            package=self.package,
            code='TEST123QR'
        )

    def test_qr_code_creation(self):
        """Test QR code creation."""
        self.assertEqual(self.qr.package, self.package)
        self.assertEqual(self.qr.code, 'TEST123QR')

    def test_qr_code_string_representation(self):
        """Test QR code string representation."""
        expected = f"QR Code for Package: TEST123QR"
        self.assertEqual(str(self.qr), expected)
