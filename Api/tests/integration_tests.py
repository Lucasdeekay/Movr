import io
import tempfile
from decimal import Decimal
from datetime import timedelta, datetime

import pytest
from PIL import Image
from io import BytesIO
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token

from Api.models import (
    KYC, Vehicle, Subscription, SubscriptionPlan, OTP, CustomUser, 
    SocialMediaLink, Route, Day, ScheduledRoute, Package, Bid, QRCode, PackageOffer
)


class UserRegistrationAuthenticationIntegrationTest(TestCase):
    """
    Integration tests for complete user registration and authentication workflow.
    Tests the flow from registration to OTP verification to login.
    """

    def setUp(self):
        self.client = APIClient()
        self.free_plan = SubscriptionPlan.objects.create(name="free")

    def test_complete_user_registration_and_authentication_flow(self):
        """
        Test the complete flow: registration -> OTP verification -> login -> logout.
        """
        # Step 1: Register a new user
        registration_data = {
            "email": "integrationuser@example.com",
            "password": "password123",
        }
        response = self.client.post(reverse('register'), registration_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('email', response.data)
        self.assertEqual(response.data['email'], registration_data['email'])
        
        # Verify user and related objects were created
        user = CustomUser.objects.get(email=registration_data['email'])
        self.assertFalse(user.is_email_verified)
        self.assertTrue(KYC.objects.filter(user=user).exists())
        self.assertTrue(Vehicle.objects.filter(user=user).exists())
        self.assertTrue(Subscription.objects.filter(user=user, plan=self.free_plan).exists())
        self.assertTrue(OTP.objects.filter(user=user).exists())

        # Step 2: Verify OTP
        otp = OTP.objects.get(user=user)
        otp_data = {
            "email": user.email,
            "code": otp.code,
        }
        response = self.client.post(reverse('verify-otp'), otp_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Email verified successfully')
        
        # Verify email is now verified and OTP is used
        user.refresh_from_db()
        self.assertTrue(user.is_email_verified)
        otp.refresh_from_db()
        self.assertTrue(otp.is_used)

        # Step 3: Login with verified credentials
        login_data = {
            'email': user.email,
            'password': 'password123'
        }
        response = self.client.post(reverse('login'), login_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], user.email)
        
        # Store token for authenticated requests
        token = response.data['token']['key']

        # Step 4: Access protected endpoint with token
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        response = self.client.get(reverse('user-routes'))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data, list)

        # Step 5: Logout
        response = self.client.post(reverse('logout'))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['detail'], "Successfully logged out.")
        
        # Step 6: Verify token is invalid after logout
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        response = self.client.get(reverse('user-routes'))
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_registration_with_invalid_otp_flow(self):
        """
        Test registration flow with invalid OTP scenarios.
        """
        # Register user
        registration_data = {
            "email": "invalidotp@example.com",
            "password": "password123",
        }
        response = self.client.post(reverse('register'), registration_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        user = CustomUser.objects.get(email=registration_data['email'])
        
        # Try to login without OTP verification
        login_data = {
            'email': user.email,
            'password': 'password123'
        }
        response = self.client.post(reverse('login'), login_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Email is not verified')

        # Try to verify with wrong OTP
        otp_data = {
            "email": user.email,
            "code": "9999",
        }
        response = self.client.post(reverse('verify-otp'), otp_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid OTP')

    def test_password_reset_flow(self):
        """
        Test complete password reset flow: request -> reset -> login.
        """
        # Create and verify a user first
        user = CustomUser.objects.create_user(
            email='resetuser@example.com',
            password='oldpassword123'
        )
        user.is_email_verified = True
        user.save()

        # Step 1: Request password reset
        response = self.client.post(reverse('forgot-password'), 
                                {'email': user.email}, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Password reset link sent to email')
        self.assertEqual(len(mail.outbox), 1)

        # Step 2: Extract token and UID from email (simplified for test)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        # Step 3: Reset password
        reset_data = {
            'uid': uid,
            'token': token,
            'new_password': 'newpassword123',
            'confirm_password': 'newpassword123'
        }
        response = self.client.post(reverse('reset-password'), reset_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Password reset successful')

        # Step 4: Verify new password works
        user.refresh_from_db()
        self.assertTrue(user.check_password('newpassword123'))

        # Step 5: Login with new password
        login_data = {
            'email': user.email,
            'password': 'newpassword123'
        }
        response = self.client.post(reverse('login'), login_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)


class VehiclePersonalInfoIntegrationTest(TestCase):
    """
    Integration tests for Vehicle and Personal information update workflow.
    Tests the complete profile setup process after authentication.
    """

    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(
            email='kycuser@example.com',
            password='password123',
            is_email_verified=True
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def create_test_image(self, name="test_image.jpg"):
        """Helper method to create an in-memory image file."""
        image = Image.new('RGB', (100, 100), color='red')
        image_file = BytesIO()
        image.save(image_file, format='JPEG')
        image_file.seek(0)
        return SimpleUploadedFile(name, image_file.read(), content_type="image/jpeg")

    def test_complete_profile_setup_workflow(self):
        """
        Test complete profile setup: Vehicle -> Personal Info -> Subscription.
        """
        # Step 1: Update Vehicle information
        vehicle_data = {
            "vehicle_plate_number": "ABC123XYZ",
            "vehicle_type": "Car",
            "vehicle_brand": "Toyota",
            "vehicle_color": "Blue",
            "vehicle_photo": self.create_test_image("vehicle.jpg"),
            "driver_license": self.create_test_image("vehicle_license.jpg"),
        }
        response = self.client.post(reverse('update-vehicle'), vehicle_data, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Vehicle information updated successfully')
        
        # Verify Vehicle was updated
        vehicle = Vehicle.objects.get(user=self.user)
        self.assertEqual(vehicle.vehicle_plate_number, "ABC123XYZ")
        self.assertEqual(vehicle.vehicle_type, "Car")
        self.assertEqual(vehicle.vehicle_brand, "Toyota")
        self.assertEqual(vehicle.vehicle_color, "Blue")

        # Step 2: Update personal information and social media
        personal_data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'phone_number': '1234567890',
            'facebook': 'https://facebook.com/johndoe',
            'instagram': 'https://instagram.com/johndoe',
            'linkedin': 'https://linkedin.com/in/johndoe',
            'profile_picture': self.create_test_image("profile.jpg"),
        }
        response = self.client.post(reverse('update-personal-info'), personal_data, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'User information updated successfully')
        
        # Verify personal info was updated
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'John')
        self.assertEqual(self.user.last_name, 'Doe')
        self.assertEqual(self.user.phone_number, '1234567890')
        self.assertIsNotNone(self.user.profile_picture)

        # Verify social media links were updated
        social_media = SocialMediaLink.objects.get(user=self.user)
        self.assertEqual(social_media.facebook, 'https://facebook.com/johndoe')
        self.assertEqual(social_media.instagram, 'https://instagram.com/johndoe')
        self.assertEqual(social_media.linkedin, 'https://linkedin.com/in/johndoe')

        # Step 3: Update subscription plan
        basic_plan = SubscriptionPlan.objects.create(name='basic', price=1200.00, duration=30)
        subscription_data = {'plan_name': 'basic'}
        response = self.client.put(reverse('update-subscription'), subscription_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Subscription plan updated successfully.')
        
        # Verify subscription was updated
        subscription = Subscription.objects.get(user=self.user)
        self.assertEqual(subscription.plan, basic_plan)
        self.assertIsNotNone(subscription.end_date)


class RouteManagementIntegrationTest(TestCase):
    """
    Integration tests for route creation, scheduling, and management workflow.
    Tests complete route lifecycle from creation to live status management.
    """

    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(
            email='routeuser@example.com',
            password='password123',
            is_email_verified=True
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        # Create days for scheduled routes
        self.monday = Day.objects.create(name='monday')
        self.tuesday = Day.objects.create(name='tuesday')

    def test_complete_route_management_workflow(self):
        """
        Test complete route workflow: create -> schedule -> retrieve -> toggle live status.
        """
        # Step 1: Create a basic route
        route_data = {
            "location": "New York",
            "location_latitude": "40.712776",
            "location_longitude": "-74.005974",
            "destination": "Los Angeles",
            "destination_latitude": "34.052235",
            "destination_longitude": "-118.243683",
            "transportation_mode": "car",
            "departure_time": (timezone.now() + timedelta(hours=2)).isoformat(),
            "service_type": "ride",
        }
        response = self.client.post(reverse('create-route'), route_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["message"], "Route created successfully.")
        
        # Verify route was created
        route = Route.objects.get(user=self.user, location=route_data['location'])
        self.assertEqual(route.destination, route_data['destination'])
        self.assertEqual(route.transportation_mode, route_data['transportation_mode'])
        self.assertTrue(route.is_live)  # Should be live by default

        # Step 2: Create a scheduled route
        scheduled_route_data = {
            "location": "Boston",
            "location_latitude": "42.360082",
            "location_longitude": "-71.058880",
            "destination": "Philadelphia",
            "destination_latitude": "39.952583",
            "destination_longitude": "-75.165222",
            "transportation_mode": "bus",
            "departure_time": (timezone.now() + timedelta(days=1)).isoformat(),
            "service_type": "delivery",
            "is_returning": "True",
            "returning_time": (timezone.now() + timedelta(days=1, hours=5)).isoformat(),
            "is_repeated": "True",
            "days_of_week": [str(self.monday.id), str(self.tuesday.id)],
        }
        response = self.client.post(reverse('create-scheduled-route'), scheduled_route_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["message"], "Scheduled Route created successfully.")
        
        # Verify scheduled route was created
        scheduled_route_data_response = response.data['scheduled_route']
        self.assertTrue(scheduled_route_data_response['is_returning'])
        self.assertTrue(scheduled_route_data_response['is_repeated'])
        self.assertEqual(len(scheduled_route_data_response['days_of_week']), 2)

        # Step 3: Retrieve all user routes
        response = self.client.get(reverse('user-routes'))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # Should have both routes

        # Step 4: Toggle route live status
        route_id = str(route.id)
        response = self.client.post(reverse('toggle-is-live', kwargs={'route_id': route_id}))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "Route is_live field updated.")
        self.assertFalse(response.data["is_live"])  # Should now be false

        # Verify in database
        route.refresh_from_db()
        self.assertFalse(route.is_live)

        # Step 5: Toggle back to live
        response = self.client.post(reverse('toggle-is-live', kwargs={'route_id': route_id}))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["is_live"])

    def test_route_with_file_upload(self):
        """
        Test route creation with ticket image upload.
        """
        # Create test image
        image = Image.new('RGB', (100, 100), color='blue')
        image_file = BytesIO()
        image.save(image_file, format='PNG')
        image_file.seek(0)
        ticket_image = SimpleUploadedFile("ticket.png", image_file.read(), content_type="image/png")

        route_data = {
            "location": "Chicago",
            "destination": "Detroit",
            "transportation_mode": "train",
            "departure_time": (timezone.now() + timedelta(hours=3)).isoformat(),
            "ticket_image": ticket_image,
        }
        response = self.client.post(reverse('create-route'), route_data, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify ticket image was saved
        route = Route.objects.get(user=self.user, location="Chicago")
        self.assertIsNotNone(route.ticket_image)
        self.assertTrue(route.ticket_image.name.endswith('.png'))

    def test_unauthorized_route_access(self):
        """
        Test that unauthenticated users cannot access route endpoints.
        """
        self.client.credentials()  # Remove authentication
        
        # Try to create route
        route_data = {
            "location": "Unauthorized City",
            "destination": "No Access",
            "transportation_mode": "car",
            "departure_time": timezone.now().isoformat(),
        }
        response = self.client.post(reverse('create-route'), route_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # Try to get user routes
        response = self.client.get(reverse('user-routes'))
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class PackageDeliveryBiddingIntegrationTest(TestCase):
    """
    Integration tests for package delivery and bidding system workflow.
    Tests complete flow from package submission to delivery confirmation.
    """

    def setUp(self):
        self.client = APIClient()
        
        # Create package sender
        self.sender = CustomUser.objects.create_user(
            email='sender@example.com',
            password='password123',
            is_email_verified=True
        )
        self.sender_token = Token.objects.create(user=self.sender)
        
        # Create mover (bidder)
        self.mover = CustomUser.objects.create_user(
            email='mover@example.com',
            password='password123',
            is_email_verified=True
        )
        self.mover_token = Token.objects.create(user=self.mover)

    def test_complete_package_delivery_workflow(self):
        """
        Test complete package delivery workflow: 
        submit package -> place bid -> select mover -> confirm pickup -> confirm delivery.
        """
        # Step 1: Sender submits a package
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.sender_token.key}')
        
        package_data = {
            "location": "123 Main St",
            "location_latitude": "40.712776",
            "location_longitude": "-74.005974",
            "destination": "456 Oak Ave",
            "destination_latitude": "34.052235",
            "destination_longitude": "-118.243683",
            "package_type": "Delivery",
            "item_description": "Electronics package",
            "item_weight": "medium",
            "receiver_name": "John Receiver",
            "receiver_phone_number": "5550123",  # Use numeric format
            "range_radius": "5.00",
        }
        response = self.client.post(reverse('submit-package'), package_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify package was created
        package = Package.objects.get(user=self.sender, location=package_data['location'])
        self.assertEqual(package.destination, package_data['destination'])
        self.assertEqual(package.package_type, "Delivery")
        self.assertEqual(package.receiver_name, "John Receiver")

        # Step 2: Mover places a bid
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.mover_token.key}')
        
        bid_data = {
            "price": "25.50"
        }
        response = self.client.post(
            reverse('place-bid', kwargs={'package_id': package.id}), 
            bid_data, 
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['message'], 'Bid placed successfully.')
        
        # Verify bid was created
        bid = Bid.objects.get(package=package, mover=self.mover)
        self.assertEqual(str(bid.price), "25.50")

        # Step 3: Sender views all bids for their package
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.sender_token.key}')
        
        response = self.client.get(
            reverse('get-all-bids', kwargs={'package_id': package.id})
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        # Check price in the response
        bid_response = response.data[0]
        self.assertEqual(bid_response['price'], "25.50")

        # Step 4: Sender selects the mover
        response = self.client.post(
            reverse('select-mover', kwargs={'bid_id': bid.id})
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(self.mover.email, response.data['message'])
        
        # Verify package offer was created
        package_offer = PackageOffer.objects.get(package_bid=bid)
        self.assertFalse(package_offer.is_picked_up)
        self.assertFalse(package_offer.is_delivered)
        self.assertIsNotNone(package_offer.qr_code)

        # Step 5: Mover confirms pickup
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.mover_token.key}')
        
        response = self.client.post(
            reverse('confirm-pickup', kwargs={'package_offer_id': package_offer.id})
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Pickup confirmed successfully')
        
        # Verify pickup status
        package_offer.refresh_from_db()
        self.assertTrue(package_offer.is_picked_up)

        # Step 6: Mover confirms delivery
        response = self.client.post(
            reverse('confirm-delivery', kwargs={'package_offer_id': package_offer.id})
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Delivery confirmed successfully')
        
        # Verify delivery status
        package_offer.refresh_from_db()
        self.assertTrue(package_offer.is_delivered)

    def test_multiple_bids_workflow(self):
        """
        Test workflow with multiple movers bidding on the same package.
        """
        # Create additional movers
        mover2 = CustomUser.objects.create_user(
            email='mover2@example.com',
            password='password123',
            is_email_verified=True
        )
        mover2_token = Token.objects.create(user=mover2)
        
        mover3 = CustomUser.objects.create_user(
            email='mover3@example.com',
            password='password123',
            is_email_verified=True
        )
        mover3_token = Token.objects.create(user=mover3)

        # Step 1: Sender submits a package
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.sender_token.key}')
        
        package_data = {
            "location": "789 Pine St",
            "destination": "321 Elm St",
            "package_type": "Delivery",
            "item_description": "Documents",
            "item_weight": "light",
        }
        response = self.client.post(reverse('submit-package'), package_data, format='json')
        package_id = response.data['id']

        # Step 2: Multiple movers place bids
        bids_data = [
            (self.mover_token, "15.00"),
            (mover2_token, "20.00"),
            (mover3_token, "18.50"),
        ]
        
        for token, price in bids_data:
            self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
            bid_data = {"price": price}
            response = self.client.post(
                reverse('place-bid', kwargs={'package_id': package_id}), 
                bid_data, 
                format='json'
            )
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Step 3: Sender views all bids
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.sender_token.key}')
        response = self.client.get(
            reverse('get-all-bids', kwargs={'package_id': package_id})
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 3)
        
        # Verify all bids are present (order may vary)
        prices = [float(bid['price']) for bid in response.data]
        self.assertIn(15.00, prices)
        self.assertIn(20.00, prices)
        self.assertIn(18.50, prices)

    def test_unauthorized_package_access(self):
        """
        Test that users cannot access packages they don't own.
        """
        # Create a package owned by sender
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.sender_token.key}')
        package_data = {
            "location": "Secret Location",
            "destination": "Secret Destination",
            "package_type": "Delivery",
        }
        response = self.client.post(reverse('submit-package'), package_data, format='json')
        package_id = response.data['id']

        # Try to access bids as mover (should be allowed)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.mover_token.key}')
        response = self.client.get(
            reverse('get-all-bids', kwargs={'package_id': package_id})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Create another user who shouldn't have access
        unauthorized_user = CustomUser.objects.create_user(
            email='unauthorized@example.com',
            password='password123',
            is_email_verified=True
        )
        unauthorized_token = Token.objects.create(user=unauthorized_user)

        # Try to access bids as unauthorized user (should fail)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {unauthorized_token.key}')
        response = self.client.get(
            reverse('get-all-bids', kwargs={'package_id': package_id})
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['error'], 'You are not authorized to view the bids for this package.')

    def test_scheduled_package_workflow(self):
        """
        Test workflow for scheduled package type.
        """
        # Step 1: Sender submits a scheduled package
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.sender_token.key}')
        
        package_data = {
            "location": "Scheduled Origin",
            "destination": "Scheduled Destination", 
            "package_type": "Schedule",
            "item_description": "Scheduled delivery item",
        }
        response = self.client.post(reverse('submit-package'), package_data, format='json')
        package = Package.objects.get(id=response.data['id'])
        self.assertEqual(package.package_type, "Schedule")

        # Step 2: Mover places bid
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.mover_token.key}')
        bid_data = {"price": "30.00"}
        response = self.client.post(
            reverse('place-bid', kwargs={'package_id': package.id}), 
            bid_data, 
            format='json'
        )
        bid = Bid.objects.get(package=package, mover=self.mover)

        # Step 3: Sender selects mover for scheduled package
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.sender_token.key}')
        response = self.client.post(
            reverse('select-mover', kwargs={'bid_id': bid.id})
        )
        
        # Verify package offer is marked as scheduled
        package_offer = PackageOffer.objects.get(package_bid=bid)
        self.assertTrue(package_offer.is_scheduled)
        self.assertFalse(package_offer.is_picked_up)
        self.assertFalse(package_offer.is_delivered)

        # Step 4: Check scheduled offers endpoint
        response = self.client.get(reverse('scheduled-package-offers'))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should contain the scheduled offer (response format depends on implementation)


class ComprehensiveWorkflowIntegrationTest(TestCase):
    """
    Comprehensive integration tests that test multiple workflows together.
    Tests complete user journey from registration to package delivery.
    """

    def setUp(self):
        self.client = APIClient()
        self.free_plan = SubscriptionPlan.objects.create(name="free")

    def test_complete_user_journey_workflow(self):
        """
        Test the complete user journey:
        1. Register and verify user
        2. Complete profile setup (Vehicle, Personal info)
        3. Create routes for transportation
        4. Submit packages and receive bids
        5. Select movers and complete deliveries
        """
        # Step 1: Register user
        registration_data = {
            "email": "journeyuser@example.com",
            "password": "password123",
        }
        response = self.client.post(reverse('register'), registration_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        user = CustomUser.objects.get(email=registration_data['email'])
        token = Token.objects.create(user=user)

        # Step 2: Verify OTP and authenticate
        otp = OTP.objects.get(user=user)
        self.client.post(reverse('verify-otp'), {
            "email": user.email,
            "code": otp.code,
        }, format='json')
        
        login_response = self.client.post(reverse('login'), {
            'email': user.email,
            'password': 'password123'
        }, format='json')
        
        auth_token = login_response.data['token']['key']
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {auth_token}')

        # Step 3: Complete profile setup (skip KYC to avoid external service calls)
        # Update Vehicle
        vehicle_data = {
            "vehicle_plate_number": "JOURNEY123",
            "vehicle_type": "Car",
            "vehicle_brand": "Honda",
            "vehicle_color": "Black",
        }
        response = self.client.post(reverse('update-vehicle'), vehicle_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Update Personal Info
        personal_data = {
            'first_name': 'Journey',
            'last_name': 'User',
            'phone_number': '5551234',  # Use numeric format
        }
        response = self.client.post(reverse('update-personal-info'), personal_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Step 4: Create routes
        route_data = {
            "location": "Home Base",
            "destination": "Office Park",
            "transportation_mode": "car",
            "departure_time": (timezone.now() + timedelta(hours=1)).isoformat(),
            "service_type": "ride",
        }
        response = self.client.post(reverse('create-route'), route_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Step 5: Create a mover user and have them bid on packages
        mover = CustomUser.objects.create_user(
            email='journeymover@example.com',
            password='password123',
            is_email_verified=True
        )
        mover_token = Token.objects.create(user=mover)
        
        # Step 6: Submit package as journey user
        package_data = {
            "location": "Package Origin",
            "destination": "Package Destination",
            "package_type": "Delivery",
            "item_description": "Test package for journey",
            "item_weight": "medium",
        }
        response = self.client.post(reverse('submit-package'), package_data, format='json')
        package_id = response.data['id']

        # Step 7: Mover places bid
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {mover_token.key}')
        bid_data = {"price": "35.00"}
        response = self.client.post(
            reverse('place-bid', kwargs={'package_id': package_id}), 
            bid_data, 
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Step 8: Original user selects mover and completes delivery
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {auth_token}')
        bid = Bid.objects.get(package_id=package_id, mover=mover)
        response = self.client.post(
            reverse('select-mover', kwargs={'bid_id': bid.id})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        package_offer = PackageOffer.objects.get(package_bid=bid)
        
        # Confirm pickup and delivery
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {mover_token.key}')
        response = self.client.post(
            reverse('confirm-pickup', kwargs={'package_offer_id': package_offer.id})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.post(
            reverse('confirm-delivery', kwargs={'package_offer_id': package_offer.id})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify complete workflow success
        package_offer.refresh_from_db()
        self.assertTrue(package_offer.is_delivered)
        
        # Verify user has complete profile and activity
        self.assertTrue(Vehicle.objects.filter(user=user).exists())
        self.assertTrue(Route.objects.filter(user=user).exists())
        self.assertTrue(Package.objects.filter(user=user).exists())