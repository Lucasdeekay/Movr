import io
import pdb
import tempfile
from _decimal import Decimal
from datetime import timedelta, datetime

import pytest
from PIL import Image
from io import BytesIO
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, RequestFactory
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.timezone import make_aware
from rest_framework.exceptions import AuthenticationFailed
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.test import APIClient, APITestCase
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token

from Api.models import KYC, Vehicle, Subscription, SubscriptionPlan, OTP, CustomUser, SocialMediaLink, Route, Day, \
    ScheduledRoute, Package, Bid, QRCode, PackageOffer

from Api.models import SubscriptionPlan
from Api.views import get_user_from_token, RegisterView

#
# class GetUserFromTokenTestCase(TestCase):
#     """
#     Test cases for the get_user_from_token function using Django's TestCase.
#     """
#
#     @classmethod
#     def setUpTestData(cls):
#         """
#         Set up test data for the entire TestCase class. This method is executed once for the test class.
#         """
#         cls.factory = RequestFactory()
#         cls.user_model = get_user_model()
#
#         # Create a test user and token
#         cls.user = cls.user_model.objects.create_user(
#             email='testuser@example.com', password='password123'
#         )
#         cls.token = Token.objects.create(user=cls.user)
#
#     def test_get_user_from_valid_token(self):
#         """
#         Test that a valid token returns the correct user.
#         """
#         request = self.factory.get(
#             '/fake-url/', HTTP_AUTHORIZATION=f'Token {self.token.key}'
#         )
#
#         result_user = get_user_from_token(request)
#         self.assertEqual(result_user, self.user)
#
#     def test_get_user_from_invalid_token(self):
#         """
#         Test that an invalid token raises AuthenticationFailed.
#         """
#         request = self.factory.get(
#             '/fake-url/', HTTP_AUTHORIZATION='Token invalidtoken123'
#         )
#
#         with self.assertRaises(AuthenticationFailed) as context:
#             get_user_from_token(request)
#
#         self.assertEqual(str(context.exception), 'Invalid token')
#
#     def test_get_user_from_missing_token(self):
#         """
#         Test that a missing token raises AuthenticationFailed.
#         """
#         request = self.factory.get('/fake-url/')
#
#         with self.assertRaises(AuthenticationFailed) as context:
#             get_user_from_token(request)
#
#         self.assertEqual(str(context.exception), 'Invalid token')
#
#
class RegisterViewTestCase(APITestCase):
    """
    Test cases for the RegisterView API view.
    """

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('register')  # Replace with the actual URL name for registration
        # Create a "free" SubscriptionPlan for the test
        self.free_plan = SubscriptionPlan.objects.create(name="free")

        # Create a user and force authenticate
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com",
            password="password123",
        )
        self.user.is_email_verified = False
        self.user.save()

        return super().setUp()

    def tearDown(self):
        return super().tearDown()

    def test_successful_registration(self):
        """
        Test that a valid registration request successfully creates a user,
        associated KYC, Vehicle, and Subscription objects, and sends an OTP.
        """

        data = {
            "email": "newuser@example.com",
            "password": "password123",
        }
        response = self.client.post(self.url, data, format='json')

        # Check for a successful response
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify the user was created
        user = CustomUser.objects.filter(email=data['email']).first()
        self.assertIsNotNone(user)

        # Check that the password was set
        self.assertTrue(user.check_password(data['password']))

# Verify KYC, Vehicle, and Subscription objects are created
        self.assertTrue(KYC.objects.filter(user=user).exists())
        self.assertTrue(Vehicle.objects.filter(user=user).exists())
        self.assertTrue(Subscription.objects.filter(user=user, plan=self.free_plan).exists())

        # Check that the subscription end date is set to 3 days from now
        subscription = Subscription.objects.get(user=user, plan=self.free_plan)
        expected_end_date = timezone.now().date() + timedelta(days=3)
        self.assertEqual(subscription.end_date, expected_end_date)

        # Check that an OTP was generated and associated with the user
        self.assertTrue(OTP.objects.filter(user=user).exists())

    def test_registration_with_missing_fields(self):
        """
        Test that a registration request with missing fields returns a 400 error.
        """
        data = {"email": "newuser@example.com"}  # Missing password
        response = self.client.post(self.url, data, format='json')

        # Check for a 400 response and an error message about missing fields
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

    def test_registration_with_invalid_email(self):
        """
        Test that a registration request with an invalid email returns a 400 error.
        """
        data = {
            "email": "invalidemail",  # Invalid email format
            "password": "password123",
        }
        response = self.client.post(self.url, data, format='json')

        # Check for a 400 response and an error message about invalid email
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)


class VerifyOTPViewTestCase(APITestCase):
    """
    Test cases for the VerifyOTPView API view.
    """

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('verify-otp')  # Replace with the actual URL name for OTP verification

        # Create a test user
        self.user = get_user_model().objects.create_user(
            email="testuser@example.com",
            password="password123",
        )
        self.user.is_email_verified = False
        self.user.save()

        # Create an OTP for the test user
        self.otp = OTP.objects.create(user=self.user)

    def tearDown(self):
        return super().tearDown()

    def test_successful_otp_verification(self):
        """
        Test that a valid OTP verification request successfully verifies the user's email.
        """
        data = {
            "email": self.user.email,
            "code": self.otp.code,  # Using the correct OTP code
        }
        response = self.client.post(self.url, data, format='json')

        # Check for a successful response
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Email verified successfully')

        # Verify that the user's email is marked as verified
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_email_verified)

        # Check that the OTP is marked as used
        self.otp.refresh_from_db()
        self.assertTrue(self.otp.is_used)

    def test_otp_already_used(self):
        """
        Test that an OTP verification request with an already used OTP returns an error.
        """
        # Mark the OTP as used
        self.otp.is_used = True
        self.otp.save()

        data = {
            "email": self.user.email,
            "code": self.otp.code,
        }
        response = self.client.post(self.url, data, format='json')

        # Check for a 400 response and an error message about the OTP being used
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'OTP has already been used')

    def test_invalid_otp_code(self):
        """
        Test that an OTP verification request with an invalid code returns an error.
        """
        data = {
            "email": self.user.email,
            "code": "wrongcode",  # Using an incorrect OTP code
        }
        response = self.client.post(self.url, data, format='json')

        # Check for a 400 response and an error message about an invalid OTP
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid OTP')


class ResendOTPViewTests(APITestCase):

    def setUp(self):
        self.client = APIClient()
        self.valid_email = 'testuser@example.com'
        self.invalid_email = 'invalid@example.com'

        # Create a test user
        self.user = CustomUser.objects.create_user(
            email=self.valid_email,
            password="password123"
        )

    def test_resend_otp_success(self):
        """
        Test resending OTP with a valid email.
        """
        url = reverse('resend-otp')  # Update with your actual URL name if different
        response = self.client.post(url, data={'email': self.valid_email}, format='json')

        # Check response status code
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check response message
        self.assertEqual(response.data['message'], 'OTP sent to email')

        # Check if OTP is created
        otp_exists = OTP.objects.filter(user=self.user).exists()
        self.assertTrue(otp_exists)

        # Verify OTP expiration time
        otp = OTP.objects.get(user=self.user)
        self.assertEqual(otp.expires_at, otp.created_at + timezone.timedelta(hours=1))

    def test_resend_otp_invalid_email(self):
        """
        Test resending OTP with an invalid email.
        """
        url = reverse('resend-otp')  # Update with your actual URL name if different
        response = self.client.post(url, data={'email': self.invalid_email}, format='json')

        # Check response status code
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Check error message
        self.assertEqual(response.data['error'], 'Invalid email or phone number')

        # Check that no OTP is created
        otp_exists = OTP.objects.filter(user__email=self.invalid_email).exists()
        self.assertFalse(otp_exists)


class LoginViewTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('login')  # Update with your actual URL name if different

        # Create a test user with a verified email
        self.user_verified = CustomUser.objects.create_user(
            email='verified@example.com',
            password='password123',
            is_email_verified=True
        )

        # Create a test user with an unverified email
        self.user_unverified = CustomUser.objects.create_user(
            email='unverified@example.com',
            password='password123',
            is_email_verified=False
        )

    def test_login_success(self):
        """
        Test successful login with correct credentials and verified email.
        """
        response = self.client.post(self.login_url, data={
            'email': self.user_verified.email,
            'password': 'password123'
        }, format='json')

        # Check response status
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check that token and user data are returned
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], self.user_verified.email)

    def test_login_invalid_email(self):
        """
        Test login with an invalid email that does not exist.
        """
        response = self.client.post(self.login_url, data={
            'email': 'invalid@example.com',
            'password': 'password123'
        }, format='json')

        # Check response status
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Check error message
        self.assertEqual(response.data['error'], 'Invalid email or phone number')

    def test_login_unverified_email(self):
        """
        Test login with a valid user but unverified email.
        """
        response = self.client.post(self.login_url, data={
            'email': self.user_unverified.email,
            'password': 'password123'
        }, format='json')

        # Check response status
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Check error message
        self.assertEqual(response.data['error'], 'Email is not verified')

    def test_login_invalid_credentials(self):
        """
        Test login with valid email but incorrect password.
        """
        response = self.client.post(self.login_url, data={
            'email': self.user_verified.email,
            'password': 'wrongpassword'
        }, format='json')

        # Check response status
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Check error message
        self.assertEqual(response.data['error'], 'Invalid credentials')


class LogoutViewTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('login')  # URL name for login view
        self.logout_url = reverse('logout')  # URL name for logout view

        # Create a test user
        self.user = CustomUser.objects.create_user(
            email='testuser@example.com',
            password='password123',
            is_email_verified=True  # Ensure the email is verified for login
        )

    def login_user(self):
        """
        Helper method to log in the user and set the authorization token.
        """
        login_response = self.client.post(self.login_url, data={
            'email': self.user.email,
            'password': 'password123'
        }, format='json')

        # Retrieve the token from the login response
        self.token = login_response.data['token']['key']
        # Set the token in the header for subsequent requests
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def test_logout_success(self):
        """
        Test successful logout after logging in.
        """
        # Log in the user first
        self.login_user()

        # Send logout request
        response = self.client.post(self.logout_url)

        # Check response status
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check response message
        self.assertEqual(response.data['detail'], "Successfully logged out.")

        # Verify that the token has been deleted
        token_exists = Token.objects.filter(user=self.user).exists()
        self.assertFalse(token_exists)

    def test_logout_with_invalid_token(self):
        """
        Test logout with an invalid token after logging in.
        """
        # Log in the user first
        self.login_user()

        # Set an invalid token in the header
        self.client.credentials(HTTP_AUTHORIZATION='Token invalidtoken123')

        response = self.client.post(self.logout_url)

        # Check response status
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # Check response message
        self.assertEqual(response.data['detail'], "Invalid token.")

    def test_logout_without_token(self):
        """
        Test logout without providing a token after logging in.
        """
        # Log in the user first
        self.login_user()

        # Clear the authorization header
        self.client.credentials()

        response = self.client.post(self.logout_url)

        # Check response status
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # Check response message
        self.assertEqual(response.data['detail'], "Authentication credentials were not provided.")


class ForgotPasswordRequestOTPViewTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('forgot-password')  # Update this to match your URL configuration

        # Create a test user
        self.user = CustomUser.objects.create_user(
            email='testuser@example.com',
            password='password123',
            is_email_verified=True
        )

    def test_password_reset_request_success(self):
        """
        Test a successful password reset request.
        """
        response = self.client.post(self.url, data={'email': self.user.email}, format='json')

        # Check if the response status is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Password reset link sent to email')

        # Check if an email was sent
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('Password Reset Request', mail.outbox[0].subject)
        self.assertIn(self.user.email, mail.outbox[0].to)

    def test_password_reset_request_user_not_found(self):
        """
        Test password reset request with a non-existent email.
        """
        response = self.client.post(self.url, data={'email': 'nonexistent@example.com'}, format='json')

        # Check if the response status is 400 BAD REQUEST
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Email not found')


class ResetPasswordViewTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('reset-password')  # Update this to match your URL configuration

        # Create a test user
        self.user = CustomUser.objects.create_user(
            email='testuser@example.com',
            password='oldpassword123',
            is_email_verified=True
        )

        # Generate a valid token and UID for password reset
        self.uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.token = default_token_generator.make_token(self.user)

    def test_reset_password_success(self):
        """
        Test a successful password reset.
        """
        data = {
            'uid': self.uid,
            'token': self.token,
            'new_password': 'newpassword123',
            'confirm_password': 'newpassword123'
        }
        response = self.client.post(self.url, data=data, format='json')

        # Check if the response status is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Password reset successful')

        # Verify that the password has been updated
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword123'))

    def test_reset_password_mismatch(self):
        """
        Test password reset with mismatched passwords.
        """
        data = {
            'uid': self.uid,
            'token': self.token,
            'new_password': 'newpassword123',
            'confirm_password': 'differentpassword'
        }
        response = self.client.post(self.url, data=data, format='json')

        # Check if the response status is 400 BAD REQUEST
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Passwords do not match')

    def test_reset_password_invalid_user(self):
        """
        Test password reset with an invalid user ID.
        """
        invalid_uid = urlsafe_base64_encode(force_bytes(99999))  # Non-existent user ID
        data = {
            'uid': invalid_uid,
            'token': self.token,
            'new_password': 'newpassword123',
            'confirm_password': 'newpassword123'
        }
        response = self.client.post(self.url, data=data, format='json')

        # Check if the response status is 400 BAD REQUEST
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid user')

    def test_reset_password_invalid_token(self):
        """
        Test password reset with an invalid token.
        """
        invalid_token = 'invalid-token'
        data = {
            'uid': self.uid,
            'token': invalid_token,
            'new_password': 'newpassword123',
            'confirm_password': 'newpassword123'
        }
        response = self.client.post(self.url, data=data, format='json')

        # Check if the response status is 400 BAD REQUEST
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid or expired token')


class UpdateKYCViewTests(APITestCase):

    def setUp(self):
        self.url = reverse('update-kyc')  # Update this to match your URL configuration

        # Create a test user
        self.user = CustomUser.objects.create_user(
            email='testuser@example.com',
            password='password123',
            is_email_verified=True
        )
        # Generate a token for the user
        self.token = Token.objects.create(user=self.user)

        # Setup valid KYC data
        self.valid_kyc_data = {
            "bvn": "12345678901",
            "nin": "12345678901",
            "verified": True,
        }

        # Mock image file for driver_license
        self.mock_image = self.generate_test_image()
        self.valid_kyc_data_with_image = {
            "bvn": "98765432101",
            "nin": "98765432101",
            "driver_license": self.mock_image,
            "verified": False
        }

        self.invalid_kyc_data = {
            "bvn": "12345",  # Invalid BVN (should be 11 digits)
            "nin": "",
            "verified": True
        }

    def generate_test_image(self):
        """Generate a valid in-memory image file for testing."""
        image = Image.new('RGB', (100, 100), color='red')
        image_file = io.BytesIO()
        image.save(image_file, format='JPEG')
        image_file.seek(0)

        return SimpleUploadedFile(
            "driver_license.jpg",
            image_file.read(),
            content_type="image/jpeg"
        )

    def authenticate(self):
        """Helper method to authenticate the user by setting the token in the headers."""
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)

    def test_update_kyc_success(self):
        """Test a successful update of KYC information."""
        self.authenticate()  # Authenticate the user

        response = self.client.post(self.url, data=self.valid_kyc_data, format='json')

        # Check if the response status is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'KYC updated successfully')

        # Verify the KYC record in the database
        kyc = KYC.objects.get(user=self.user)
        self.assertEqual(kyc.bvn, "12345678901")
        self.assertTrue(kyc.verified)

    def test_update_kyc_with_image(self):
        """Test updating KYC with an image file (driver_license)."""
        self.authenticate()  # Authenticate the user

        response = self.client.post(self.url, data=self.valid_kyc_data_with_image, format='multipart')

        # Check if the response status is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'KYC updated successfully')

        # Verify the KYC record in the database
        kyc = KYC.objects.get(user=self.user)
        self.assertEqual(kyc.bvn, "98765432101")
        self.assertFalse(kyc.verified)
        self.assertIsNotNone(kyc.driver_license)

    def test_update_kyc_validation_error(self):
        """Test KYC update with invalid data resulting in a validation error."""
        self.authenticate()  # Authenticate the user

        response = self.client.post(self.url, data=self.invalid_kyc_data, format='json')

        # Check if the response status is 400 BAD REQUEST
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    def test_update_kyc_unauthenticated(self):
        """Test KYC update without authentication, expecting an unauthorized error."""
        response = self.client.post(self.url, data=self.valid_kyc_data, format='json')

        # Check if the response status is 401 UNAUTHORIZED
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'], 'Authentication credentials were not provided.')

    def test_create_new_kyc_record(self):
        """Test KYC update when no existing KYC record exists for the user."""
        self.authenticate()  # Authenticate the user

        # Ensure no KYC record exists initially
        self.assertFalse(KYC.objects.filter(user=self.user).exists())

        response = self.client.post(self.url, data=self.valid_kyc_data, format='json')

        # Check if the response status is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'KYC updated successfully')

        # Verify that a new KYC record was created
        self.assertTrue(KYC.objects.filter(user=self.user).exists())

    def test_update_kyc_invalid_driver_license_type(self):
        """Test that the driver_license must be a valid image file."""
        self.authenticate()  # Authenticate the user

        # Invalid driver_license (not an image)
        invalid_image = SimpleUploadedFile(
            "driver_license.txt", b"file_content", content_type="text/plain"
        )
        invalid_data = {
            "bvn": "98765432101",
            "nin": "98765432101",
            "driver_license": invalid_image
        }

        response = self.client.post(self.url, data=invalid_data, format='multipart')

        # Check if the response status is 400 BAD REQUEST
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Driver license must be an image file.')


class UpdateVehicleInfoViewTests(APITestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('update-vehicle')  # Update this to match your URL configuration

        # Create a test user
        self.user = CustomUser.objects.create_user(
            email='testuser@example.com',
            password='password123',
            is_email_verified=True
        )
        # Generate a token for the user
        self.token = Token.objects.create(user=self.user)

        # Valid vehicle data
        self.valid_vehicle_data = {
            "vehicle_plate_number": "ABC123XYZ",
            "vehicle_type": "Car",
            "vehicle_brand": "Toyota",
            "vehicle_color": "Red"
        }

        # Create a mock image using PIL
        self.mock_image = self.create_image_file("vehicle_photo.jpg")

        # Valid vehicle data with images
        self.valid_vehicle_data_with_images = {
            "vehicle_plate_number": "XYZ987ABC",
            "vehicle_type": "Truck",
            "vehicle_brand": "Ford",
            "vehicle_color": "Blue",
            "vehicle_photo": self.mock_image,
            "driver_license": self.mock_image,
            "vehicle_inspector_report": self.mock_image,
            "vehicle_insurance": self.mock_image
        }

        # Invalid vehicle data
        self.invalid_vehicle_data = {
            "vehicle_plate_number": "AB",  # Invalid (less than 4 characters)
            "vehicle_type": "Car"
        }

    def create_image_file(self, name="test_image.jpg"):
        """
        Helper method to create an in-memory image file using PIL.
        """

        """Generate a valid in-memory image file for testing."""
        image = Image.new('RGB', (100, 100), color='red')
        image_file = io.BytesIO()
        image.save(image_file, format='JPEG')
        image_file.seek(0)

        return SimpleUploadedFile(
            name,
            image_file.read(),
            content_type="image/jpeg"
        )

    def authenticate(self):
        """
        Helper method to authenticate the user by setting the token in the headers.
        """
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)

    def test_update_vehicle_success(self):
        """
        Test a successful update of vehicle information.
        """
        self.authenticate()  # Authenticate the user

        response = self.client.post(self.url, data=self.valid_vehicle_data, format='json')

        # Check if the response status is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Vehicle information updated successfully')

        # Verify the Vehicle record in the database
        vehicle = Vehicle.objects.get(user=self.user)
        self.assertEqual(vehicle.vehicle_plate_number, "ABC123XYZ")
        self.assertEqual(vehicle.vehicle_type, "Car")
        self.assertEqual(vehicle.vehicle_brand, "Toyota")
        self.assertEqual(vehicle.vehicle_color, "Red")

    def test_update_vehicle_with_images_success(self):
        """
        Test updating vehicle information with image files.
        """
        self.authenticate()  # Authenticate the user

        # Re-create mock image files to ensure they are valid
        self.valid_vehicle_data_with_images["vehicle_photo"] = self.create_image_file("vehicle_photo.jpg")
        self.valid_vehicle_data_with_images["driver_license"] = self.create_image_file("driver_license.jpg")
        self.valid_vehicle_data_with_images["vehicle_inspector_report"] = self.create_image_file(
            "vehicle_inspector_report.jpg")
        self.valid_vehicle_data_with_images["vehicle_insurance"] = self.create_image_file("vehicle_insurance.jpg")

        response = self.client.post(self.url, data=self.valid_vehicle_data_with_images, format='multipart')

        # Check if the response status is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Vehicle information updated successfully')

        # Verify the Vehicle record in the database
        vehicle = Vehicle.objects.get(user=self.user)
        self.assertEqual(vehicle.vehicle_plate_number, "XYZ987ABC")
        self.assertIsNotNone(vehicle.vehicle_photo)
        self.assertIsNotNone(vehicle.driver_license)
        self.assertIsNotNone(vehicle.vehicle_inspector_report)
        self.assertIsNotNone(vehicle.vehicle_insurance)

    def test_update_vehicle_invalid_image_type(self):
        """
        Test that only valid image files are accepted.
        """
        self.authenticate()  # Authenticate the user

        # Invalid image type (non-image file)
        invalid_file = SimpleUploadedFile(
            "file.txt", b"file_content", content_type="text/plain"
        )
        data_with_invalid_image = {
            "vehicle_plate_number": "ABC123XYZ",
            "vehicle_type": "Car",
            "vehicle_photo": invalid_file
        }

        response = self.client.post(self.url, data=data_with_invalid_image, format='multipart')

        # Check if the response status is 400 BAD REQUEST
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'vehicle_photo must be an image file.')

    def test_update_vehicle_unauthenticated(self):
        """
        Test vehicle update without authentication, expecting an unauthorized error.
        """
        response = self.client.post(self.url, data=self.valid_vehicle_data, format='json')

        # Check if the response status is 401 UNAUTHORIZED
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'], 'Authentication credentials were not provided.')


class UpdatePersonalInfoViewTests(APITestCase):

    def setUp(self):
        # Create a test user
        self.user = CustomUser.objects.create_user(
            email='testuser@example.com',
            password='testpassword123',
            phone_number='1234567890'
        )
        # Generate token for authentication
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)

        # Create social media links for the user
        self.social_media = SocialMediaLink.objects.create(
            user=self.user,
            facebook='https://facebook.com/testuser',
            instagram='https://instagram.com/testuser',
            linkedin='https://linkedin.com/in/testuser'
        )
        # URL for updating personal info
        self.url = reverse('update-personal-info')

    @staticmethod
    def create_test_image():
        """
        Helper function to create a simple image file for testing.
        """
        image = Image.new('RGB', (100, 100), color='red')
        temp_file = tempfile.NamedTemporaryFile(suffix=".jpg")
        image.save(temp_file, format='JPEG')
        temp_file.seek(0)
        return SimpleUploadedFile(
            name=temp_file.name,
            content=temp_file.read(),
            content_type='image/jpeg'
        )

    def test_update_personal_info_success(self):
        """
        Test successful update of user personal info and social media links.
        """
        data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'phone_number': '0987654321',
            'facebook': 'https://facebook.com/newuser',
            'instagram': 'https://instagram.com/newuser',
            'linkedin': 'https://linkedin.com/in/newuser',
        }
        response = self.client.post(self.url, data, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user']['first_name'], 'John')
        self.assertEqual(response.data['social_media']['facebook'], 'https://facebook.com/newuser')

    def test_update_with_invalid_profile_picture(self):
        """
        Test updating with an invalid profile picture (wrong file type).
        """
        invalid_image = SimpleUploadedFile("file.txt", b"file_content", content_type="text/plain")
        data = {
            'profile_picture': invalid_image
        }
        response = self.client.post(self.url, data, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Profile picture must be a valid image file.')

    def test_update_with_large_profile_picture(self):
        """
        Test updating with a profile picture larger than 5MB.
        """
        large_image = SimpleUploadedFile(
            "large_image.jpg", b"file_content" * 1024 * 1024 * 6, content_type="image/jpeg"
        )
        data = {
            'profile_picture': large_image
        }
        response = self.client.post(self.url, data, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Profile picture size must be under 5MB.')

    def test_update_profile_picture_success(self):
        """
        Test successful upload of a valid profile picture.
        """
        valid_image = self.create_test_image()
        data = {
            'profile_picture': valid_image
        }
        response = self.client.post(self.url, data, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('profile_picture', response.data['user'])
        self.assertTrue(response.data['user']['profile_picture'].startswith('/media/profile_pics/'))

    def test_update_with_duplicate_phone_number(self):
        """
        Test updating user info with an already existing phone number.
        """
        # Create another user with a different phone number
        CustomUser.objects.create_user(
            email='anothertestinguser@example.com',
            password='testpassword123',
            phone_number='2223333444'
        )
        data = {
            'phone_number': '2223333444'  # Duplicate phone number
        }
        response = self.client.post(self.url, data, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('user_errors', response.data)

    def test_update_with_duplicate_social_media_links(self):
        """
        Test updating social media links with an already existing link.
        """
        user = CustomUser.objects.create_user(
            email='anothertestuser@example.com',
            password='testpassword123',
            phone_number='1112223333'
        )
        SocialMediaLink.objects.create(
            user=user,
            facebook='https://facebook.com/duplicateuser'
        )
        data = {
            'facebook': 'https://facebook.com/duplicateuser'  # Duplicate Facebook link
        }
        response = self.client.post(self.url, data, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('social_media_errors', response.data)
        self.assertIn('facebook', response.data['social_media_errors'])

    def test_partial_update_success(self):
        """
        Test partial update of user info and social media links.
        """
        data = {
            'first_name': 'Jane',
            'linkedin': 'https://linkedin.com/in/newjaneuser'
        }
        response = self.client.post(self.url, data, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user']['first_name'], 'Jane')
        self.assertEqual(response.data['social_media']['linkedin'], 'https://linkedin.com/in/newjaneuser')

    def test_update_with_invalid_facebook_url(self):
        """
        Test updating social media links with an invalid Facebook URL.
        """
        data = {
            'facebook': 'invalid-url'
        }
        response = self.client.post(self.url, data, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('social_media_errors', response.data)
        self.assertIn('facebook', response.data['social_media_errors'])


class UpdateSubscriptionPlanViewTests(APITestCase):

    def setUp(self):
        # Create a test user
        self.user = CustomUser.objects.create_user(
            email='testuser@example.com',
            password='testpassword123'
        )
        # Generate token for authentication
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)

        free_plan = SubscriptionPlan.objects.create(name="free")
        Subscription.objects.create(user=self.user, plan=free_plan)

        # Create some subscription plans
        self.plan_basic = SubscriptionPlan.objects.create(
            name='basic',
            price=10.00,
            duration=30  # 30 days
        )
        self.plan_premium = SubscriptionPlan.objects.create(
            name='premium',
            price=20.00,
            duration=60  # 60 days
        )

        # URL for updating subscription plan
        self.url = reverse('update-subscription')

    def test_update_subscription_plan_success(self):
        """
        Test successful update of the subscription plan.
        """
        data = {'plan_name': 'premium'}
        response = self.client.put(self.url, data, format='json')

        # Fetch the updated subscription record
        subscription = Subscription.objects.get(user=self.user)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(subscription.plan.name, 'premium')
        self.assertEqual(subscription.plan, self.plan_premium)
        self.assertEqual(subscription.end_date, subscription.start_date + timedelta(days=self.plan_premium.duration))
        self.assertEqual(response.data['message'], 'Subscription plan updated successfully.')

    def test_update_subscription_plan_missing_name(self):
        """
        Test updating the subscription plan with a missing plan name.
        """
        data = {}
        response = self.client.put(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Plan name is required.')

    def test_update_subscription_plan_non_existent(self):
        """
        Test updating the subscription plan with a non-existent plan name.
        """
        data = {'plan_name': 'nonexistentplan'}
        response = self.client.put(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['error'], 'Subscription plan not found.')

    def test_create_new_subscription_on_plan_update(self):
        """
        Test that a new subscription is created if the user does not have an existing subscription.
        """
        data = {'plan_name': 'basic'}
        response = self.client.put(self.url, data, format='json')

        # Verify that the subscription was created
        subscription_exists = Subscription.objects.filter(user=self.user, plan=self.plan_basic).exists()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(subscription_exists)
        self.assertEqual(response.data['message'], 'Subscription plan updated successfully.')

    def test_update_existing_subscription_plan(self):
        """
        Test updating an existing subscription plan for the user.
        """
        # Get an existing subscription for the user
        existing_subscription = Subscription.objects.get(
            user=self.user
        )

        # Update to a different plan
        data = {'plan_name': 'premium'}
        response = self.client.put(self.url, data, format='json')

        # Fetch the updated subscription record
        existing_subscription.refresh_from_db()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(existing_subscription.plan.name, 'premium')
        self.assertEqual(existing_subscription.plan, self.plan_premium)
        self.assertEqual(response.data['message'], 'Subscription plan updated successfully.')

    def test_update_with_case_insensitive_plan_name(self):
        """
        Test updating the subscription plan with case-insensitive plan name input.
        """
        data = {'plan_name': 'PREMIUM'}  # Plan name in uppercase
        response = self.client.put(self.url, data, format='json')

        # Fetch the updated subscription record
        subscription = Subscription.objects.get(user=self.user)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(subscription.plan.name, 'premium')
        self.assertEqual(subscription.plan, self.plan_premium)
        self.assertEqual(response.data['message'], 'Subscription plan updated successfully.')


class CreateRouteViewTestCase(APITestCase):
    """
    Test cases for the CreateRouteView API view.
    """

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('create-route')  # Replace with your actual route name

        # Create a test user
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com",
            password="password123",
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def tearDown(self):
        self.client.credentials()  # Reset client credentials

    def test_successful_route_creation(self):
        """
        Test that a route is successfully created with valid input.
        """
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

        response = self.client.post(self.url, data, format='json')

        # Check for a successful response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["message"], "Route created successfully.")

        # Verify that the route was created
        route = Route.objects.filter(user=self.user, location=data['location'], destination=data['destination']).first()
        self.assertIsNotNone(route)
        self.assertEqual(route.transportation_mode, data['transportation_mode'])
        self.assertEqual(route.service_type, data['service_type'])

    def test_missing_required_fields(self):
        """
        Test that missing required fields return a 400 error.
        """
        data = {
            "location": "Location A",
            # Missing 'destination' and 'transportation_mode'
            "departure_time": timezone.now().isoformat(),
        }

        response = self.client.post(self.url, data, format='json')

        # Check for a 400 response and error message
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)
        self.assertEqual(
            response.data["error"],
            "Location, destination, transportation mode, and departure time are required."
        )

    def test_invalid_transportation_mode(self):
        """
        Test that an invalid transportation mode is handled properly.
        """
        data = {
            "location": "Location A",
            "location_latitude": 40.712776,
            "location_longitude": -74.005974,
            "destination": "Location B",
            "destination_latitude": 34.052235,
            "destination_longitude": -118.243683,
            "departure_time": timezone.now().isoformat(),
        }

        response = self.client.post(self.url, data, format='json')

        # Assuming your serializer or model validates transportation_mode
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_unauthenticated_user(self):
        """
        Test that an unauthenticated user cannot create a route.
        """
        self.client.credentials()  # Remove authentication
        data = {
            "location": "Location A",
            "location_latitude": 40.712776,
            "location_longitude": -74.005974,
            "destination": "Location B",
            "destination_latitude": 34.052235,
            "destination_longitude": -118.243683,
            "transportation_mode": "car",
            "departure_time": timezone.now().isoformat(),
        }

        response = self.client.post(self.url, data, format='json')

        # Check for a 401 response
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_route_creation_with_files(self):
        """
        Test route creation with an uploaded ticket image.
        """
        with open("test_ticket_image.jpg", "wb") as file:  # Create a dummy file for the test
            file.write(b"dummy content")
        with open("test_ticket_image.jpg", "rb") as ticket_image:
            data = {
                "location": "Location A",
                "location_latitude": 40.712776,
                "location_longitude": -74.005974,
                "destination": "Location B",
                "destination_latitude": 34.052235,
                "destination_longitude": -118.243683,
                "transportation_mode": "bus",
                "departure_time": timezone.now().isoformat(),
                "ticket_image": ticket_image,
            }

            response = self.client.post(self.url, data, format='multipart')

            # Check for a successful response
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(response.data["message"], "Route created successfully.")

# Verify the route was created with the ticket image
            route = Route.objects.filter(user=self.user, location=data['location'],
                                         destination=data['destination']).first()
            self.assertIsNotNone(route)
            self.assertIsNotNone(route.ticket_image)

    def test_route_creation_with_null_stop_location(self):
        """
        Test that route can be created with null/empty stop location values.
        """
        data = {
            "location": "Location A",
            "location_latitude": 40.712776,
            "location_longitude": -74.005974,
            "destination": "Location B",
            "destination_latitude": 34.052235,
            "destination_longitude": -118.243683,
            "stop_location": "",  # Empty string
            "stop_location_latitude": None,  # Null value
            "stop_location_longitude": None,  # Null value
            "transportation_mode": "car",
            "departure_time": timezone.now().isoformat(),
            "service_type": "ride",
        }

        response = self.client.post(self.url, data, format='json')

        # Check for a successful response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["message"], "Route created successfully.")

        # Verify that route was created with null stop location values
        route = Route.objects.filter(user=self.user, location=data['location'], 
                                destination=data['destination']).first()
        self.assertIsNotNone(route)
        
        # Verify stop location fields accept null/empty values
        self.assertEqual(route.stop_location, "")  # Empty string should be stored
        self.assertIsNone(route.stop_location_latitude)  # Null should be stored
        self.assertIsNone(route.stop_location_longitude)  # Null should be stored

    def test_route_creation_with_partial_stop_location(self):
        """
        Test that route can be created with partial stop location data.
        """
        data = {
            "location": "Location A",
            "location_latitude": 40.712776,
            "location_longitude": -74.005974,
            "destination": "Location B",
            "destination_latitude": 34.052235,
            "destination_longitude": -118.243683,
            "stop_location": "Stop Location C",  # Only name provided
            # latitude and longitude omitted (should be null)
            "transportation_mode": "car",
            "departure_time": timezone.now().isoformat(),
            "service_type": "ride",
        }

        response = self.client.post(self.url, data, format='json')

        # Check for a successful response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["message"], "Route created successfully.")

        # Verify that route was created with partial stop location
        route = Route.objects.filter(user=self.user, location=data['location'], 
                                destination=data['destination']).first()
        self.assertIsNotNone(route)
        
        # Verify stop location
        self.assertEqual(route.stop_location, "Stop Location C")
        self.assertIsNone(route.stop_location_latitude)  # Should be null when not provided
        self.assertIsNone(route.stop_location_longitude)  # Should be null when not provided

    def test_route_creation_with_full_stop_location(self):
        """
        Test that route can be created with complete stop location data.
        """
        data = {
            "location": "Location A",
            "location_latitude": 40.712776,
            "location_longitude": -74.005974,
            "destination": "Location B",
            "destination_latitude": 34.052235,
            "destination_longitude": -118.243683,
            "stop_location": "Stop Location C",
            "stop_location_latitude": 39.952583,
            "stop_location_longitude": -75.165222,
            "transportation_mode": "car",
            "departure_time": timezone.now().isoformat(),
            "service_type": "ride",
        }

        response = self.client.post(self.url, data, format='json')

        # Check for a successful response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["message"], "Route created successfully.")

        # Verify that route was created with complete stop location
        route = Route.objects.filter(user=self.user, location=data['location'], 
                                destination=data['destination']).first()
        self.assertIsNotNone(route)
        
        # Verify stop location fields
        self.assertEqual(route.stop_location, "Stop Location C")
        self.assertEqual(float(route.stop_location_latitude), 39.952583)
        self.assertEqual(float(route.stop_location_longitude), -75.165222)


class CreateScheduledRouteViewTestCase(APITestCase):
    """
    Test cases for the CreateScheduledRouteView API view.
    """

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('create-scheduled-route')  # Replace with your actual route name

        # Create a test user
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com",
            password="password123",
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

        # Create sample days for repeated schedule
        self.monday = Day.objects.create(name="Monday")
        self.tuesday = Day.objects.create(name="Tuesday")

    def tearDown(self):
        self.client.credentials()  # Reset client credentials

    def test_successful_scheduled_route_creation(self):
        """
        Test successful creation of a scheduled route.
        """
        data = {
            "location": "Location A",
            "location_latitude": 40.712776,
            "location_longitude": -74.005974,
            "destination": "Location B",
            "destination_latitude": 34.052235,
            "destination_longitude": -118.243683,
            "transportation_mode": "car",
            "departure_time": timezone.now().isoformat(),
            "is_returning": "True",
            "returning_time": timezone.now().isoformat(),
            "is_repeated": "True",
            "days_of_week": [self.monday.id, self.tuesday.id],
        }

        response = self.client.post(self.url, data, format='json')

        # Check for a successful response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["message"], "Scheduled Route created successfully.")

        # Verify the scheduled route was created
        scheduled_route = ScheduledRoute.objects.filter(route__user=self.user).first()
        self.assertIsNotNone(scheduled_route)
        self.assertTrue(scheduled_route.is_returning)
        self.assertTrue(scheduled_route.is_repeated)
        self.assertEqual(scheduled_route.days_of_week.count(), 2)

    def test_missing_required_fields(self):
        """
        Test that missing required fields return a 400 error.
        """
        data = {
            "location": "Location A",
            # Missing 'destination' and 'transportation_mode'
            "departure_time": timezone.now().isoformat(),
        }

        response = self.client.post(self.url, data, format='json')

        # Check for a 400 response and error message
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)
        self.assertEqual(
            response.data["error"],
            "Location, destination, transportation mode, and departure time are required."
        )

    def test_missing_days_for_repeated_route(self):
        """
        Test that a repeated route requires days of the week.
        """
        data = {
            "location": "Location A",
            "destination": "Location B",
            "transportation_mode": "bus",
            "departure_time": timezone.now().isoformat(),
            "is_repeated": "True",  # Repeated route
        }

        response = self.client.post(self.url, data, format='json')

        # Check for a 400 response and error message
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)
        self.assertEqual(response.data["error"], "Days of week must be provided if the route is repeated.")

    def test_unauthenticated_user(self):
        """
        Test that an unauthenticated user cannot create a scheduled route.
        """
        self.client.credentials()  # Remove authentication
        data = {
            "location": "Location A",
            "destination": "Location B",
            "transportation_mode": "car",
            "departure_time": timezone.now().isoformat(),
        }

        response = self.client.post(self.url, data, format='json')

        # Check for a 401 response
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_scheduled_route_with_optional_fields(self):
        """
        Test creation of a scheduled route with optional fields.
        """
        data = {
            "location": "Location A",
            "destination": "Location B",
            "transportation_mode": "car",
            "departure_time": timezone.now().isoformat(),
            # Optional fields
            "stop_location": "Stop Location A",
            "stop_location_latitude": 36.778259,
            "stop_location_longitude": -119.417931,
        }

        response = self.client.post(self.url, data, format='json')

        # Check for a successful response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["message"], "Scheduled Route created successfully.")

        # Verify the route and optional fields
        scheduled_route = ScheduledRoute.objects.filter(route__user=self.user).first()
        self.assertIsNotNone(scheduled_route)
        self.assertEqual(scheduled_route.route.stop_location, data['stop_location'])


class UserRoutesViewTestCase(APITestCase):
    """
    Test cases for the UserRoutesView API view.
    """

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('user-routes')  # Replace with the actual route name

        # Create test users
        self.user1 = CustomUser.objects.create_user(
            email="user1@example.com",
            password="password123",
        )
        self.user2 = CustomUser.objects.create_user(
            email="user2@example.com",
            password="password123",
        )

        # Create authentication tokens for the users
        self.token1 = Token.objects.create(user=self.user1)
        self.token2 = Token.objects.create(user=self.user2)

        # Create sample routes for user1
        self.route1 = Route.objects.create(
            user=self.user1,
            location="Location A",
            location_latitude=40.712776,
            location_longitude=-74.005974,
            destination="Location B",
            destination_latitude=34.052235,
            destination_longitude=-118.243683,
            transportation_mode="car",
            departure_time=make_aware(datetime.now() + timedelta(days=1)),
        )
        self.route2 = Route.objects.create(
            user=self.user1,
            location="Location C",
            location_latitude=37.774929,
            location_longitude=-122.419418,
            destination="Location D",
            destination_latitude=47.606209,
            destination_longitude=-122.332069,
            transportation_mode="bus",
            departure_time=make_aware(datetime.now() + timedelta(days=1)),
        )

    def tearDown(self):
        self.client.credentials()  # Reset client credentials

    def test_retrieve_user_routes(self):
        """
        Test retrieving routes for an authenticated user.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token1.key}')
        response = self.client.get(self.url)

        # Check for a successful response
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify the response contains the correct routes
        self.assertEqual(len(response.data), 2)
        self.assertEqual(response.data[0]["location"], self.route1.location)
        self.assertEqual(response.data[1]["location"], self.route2.location)

    def test_no_routes_for_user(self):
        """
        Test response when the authenticated user has no routes.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token2.key}')
        response = self.client.get(self.url)

        # Check for a successful response
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify the response is empty
        self.assertEqual(response.data, [])

    def test_unauthenticated_access(self):
        """
        Test that unauthenticated users cannot access the endpoint.
        """
        response = self.client.get(self.url)

        # Check for a 401 Unauthorized response
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_authenticated_user_does_not_see_other_user_routes(self):
        """
        Test that a user cannot see another user's routes.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token2.key}')
        response = self.client.get(self.url)

        # Check for a successful response
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify that the user does not see routes belonging to user1
        self.assertEqual(response.data, [])


class ToggleIsLiveRouteViewTestCase(APITestCase):
    """
    Test cases for the ToggleIsLiveRouteView API view.
    """

    def setUp(self):
        self.client = APIClient()

        # Create test users
        self.user1 = CustomUser.objects.create_user(
            email="user1@example.com",
            password="password123",
        )
        self.user2 = CustomUser.objects.create_user(
            email="user2@example.com",
            password="password123",
        )

        # Create authentication tokens for the users
        self.token1 = Token.objects.create(user=self.user1)
        self.token2 = Token.objects.create(user=self.user2)

        # Create a route for user1
        self.route = Route.objects.create(
            user=self.user1,
            location="Location A",
            location_latitude=40.712776,
            location_longitude=-74.005974,
            destination="Location B",
            destination_latitude=34.052235,
            destination_longitude=-118.243683,
            transportation_mode="car",
            departure_time=make_aware(datetime.now() + timedelta(days=1)),
            is_live=False,
        )

        # URL for the view
        self.url = reverse("toggle-is-live", kwargs={"route_id": self.route.id})

    def tearDown(self):
        self.client.credentials()  # Reset client credentials

    def test_toggle_is_live_success(self):
        """
        Ensure that an authenticated user can successfully toggle the is_live field.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token1.key}")

        # Toggle is_live (should go from False to True)
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.route.refresh_from_db()
        self.assertTrue(self.route.is_live)

        # Toggle is_live again (should go from True to False)
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.route.refresh_from_db()
        self.assertFalse(self.route.is_live)

    def test_toggle_is_live_unauthenticated(self):
        """
        Ensure that an unauthenticated user cannot toggle the is_live field.
        """
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_toggle_is_live_route_not_found(self):
        """
        Ensure that toggling a non-existent route returns a 404 error.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token1.key}")
        invalid_url = reverse("toggle-is-live", kwargs={"route_id": 9999})
        response = self.client.post(invalid_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_toggle_is_live_wrong_user(self):
        """
        Ensure that a user cannot toggle the is_live field of a route they do not own.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token2.key}")
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class PackageSubmissionViewTestCase(APITestCase):
    """
    Test cases for the PackageSubmissionView API.
    """

    def setUp(self):
        self.client = APIClient()

        # Create test users
        self.user1 = CustomUser.objects.create_user(
            email="user1@example.com",
            password="password123",
        )
        self.user2 = CustomUser.objects.create_user(
            email="user2@example.com",
            password="password123",
        )

        # Create authentication tokens
        self.token1 = Token.objects.create(user=self.user1)
        self.token2 = Token.objects.create(user=self.user2)

        # Define the URL for package submissions
        self.url = reverse("submit-package")  # Make sure your URL pattern name matches this

    def tearDown(self):
        """
        Clean up after tests.
        """
        self.client.credentials()  # Reset client credentials
        Package.objects.all().delete()  # Clear packages

    def generate_test_image(self):
        """Generate a valid in-memory image file for testing."""
        image = Image.new('RGB', (100, 100), color='red')
        image_file = io.BytesIO()
        image.save(image_file, format='JPEG')
        image_file.seek(0)

        return SimpleUploadedFile(
            "image.jpg",
            image_file.read(),
            content_type="image/jpeg"
        )

    def test_package_submission_success(self):
        """
        Ensure a package can be submitted successfully by an authenticated user.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token1.key}")

        # Create a temporary image file for testing
        item_image = self.generate_test_image()

        data = {
            "location": "Origin City",
            "location_latitude": Decimal("40.712776"),
            "location_longitude": Decimal("-74.005974"),
            "destination": "Destination City",
            "destination_latitude": Decimal("34.052235"),
            "destination_longitude": Decimal("-118.243683"),
            "package_type": "Delivery",
            "item_image": item_image,
            "item_description": "Books and gadgets",
            "item_weight": "medium",
            "receiver_name": "John Doe",
            "receiver_phone_number": "1234567890",
            "range_radius": Decimal("10.00"),
        }

        response = self.client.post(self.url, data, format="multipart")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify that the package was created
        self.assertEqual(Package.objects.count(), 1)
        package = Package.objects.first()
        self.assertEqual(package.location, "Origin City")
        self.assertEqual(package.destination, "Destination City")
        self.assertEqual(package.user, self.user1)
        self.assertEqual(package.package_type, "Delivery")
        self.assertEqual(package.item_weight, "medium")

    def test_package_submission_unauthenticated(self):
        """
        Ensure that unauthenticated users cannot submit a package.
        """
        data = {
            "location": "Origin City",
            "destination": "Destination City",
            "package_type": "Delivery",
        }

        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_package_submission_invalid_data(self):
        """
        Ensure validation errors are returned for invalid package submission data.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token1.key}")

        # Missing required fields
        data = {
            "location": "",
            "destination": "",
            "package_type": "InvalidType",  # Invalid choice
        }

        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("location", response.data)
        self.assertIn("destination", response.data)
        self.assertIn("package_type", response.data)

    def test_package_submission_with_minimal_data(self):
        """
        Ensure a package can be submitted with minimal valid data.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token1.key}")

        data = {
            "location": "Origin City",
            "destination": "Destination City",
            "package_type": "Delivery",
        }

        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify that the package was created
        package = Package.objects.first()
        self.assertEqual(package.location, "Origin City")
        self.assertEqual(package.destination, "Destination City")
        self.assertEqual(package.package_type, "Delivery")

    def test_package_submission_different_user(self):
        """
        Ensure that the package is associated with the authenticated user making the request.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token2.key}")

        data = {
            "location": "Origin City",
            "destination": "Destination City",
            "package_type": "Delivery",
        }

        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify that the package is associated with user2
        package = Package.objects.first()
        self.assertEqual(package.user, self.user2)


class PlaceBidViewTest(APITestCase):
    """
    Test case for placing a bid on a package.
    """

    def setUp(self):
        """
        Setup the test environment by creating a user, authenticating,
        and creating a package for bidding.
        """
        # Create a test user and authenticate
        self.user = CustomUser.objects.create_user(email='testuser@example.com', password='password123')
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

        # Create a package for bidding
        self.package = Package.objects.create(
            user=self.user,
            location="Test Location",
            destination="Test Destination",
            package_type="Delivery",
            item_description="Test Item",
            item_weight="medium",
            receiver_name="Receiver",
            receiver_phone_number="1234567890"
        )

        # Define the URL for the PlaceBidView endpoint
        self.url = reverse('place-bid', kwargs={'package_id': self.package.id})

    def tearDown(self):
        """
        Clean up any created data after tests are run.
        """
        self.package.delete()
        self.user.delete()

    def test_place_bid_without_price(self):
        """
        Test placing a bid without providing a price in the request.
        """
        # Send POST request without the price field
        response = self.client.post(self.url, {})

        # Assert the response status code and error message
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, {"error": "Price is required to place a bid."})

    def test_place_bid_on_non_existing_package(self):
        """
        Test placing a bid on a non-existing package.
        """
        # Use a non-existing package_id (valid UUID format but doesn't exist)
        invalid_url = reverse('place-bid', kwargs={'package_id': '12345678-1234-1234-1234-123456789abc'})

        # Send POST request with a price
        response = self.client.post(invalid_url, {'price': 100.00})

        # Assert that response status code and error message
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data, {'error': 'Package not found.'})

    def test_place_bid_successfully(self):
        """
        Test placing a bid successfully with valid data.
        """
        # Send POST request with a price
        response = self.client.post(self.url, {'price': 100.00})

        # Assert the response status code and success message
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['message'], "Bid placed successfully.")

        # Retrieve the created bid from the database
        bid = Bid.objects.get(id=response.data['bid_id'])

        # Assert that the bid details are correct
        self.assertEqual(bid.package, self.package)
        self.assertEqual(bid.mover, self.user)
        self.assertEqual(bid.price, 100.00)


class GetAllBidsViewTest(APITestCase):
    """
    Test case for retrieving all bids for a given package.
    """

    def setUp(self):
        """
        Setup the test environment by creating two users, authenticating them,
        and creating a package for one user and a bid for the package.
        """
        # Create test users
        self.user1 = CustomUser.objects.create_user(email='user1@example.com', password='password123')
        self.user2 = CustomUser.objects.create_user(email='user2@example.com', password='password123')

        # Create a test package for user1
        self.package1 = Package.objects.create(
            user=self.user1,
            location="Test Location 1",
            destination="Test Destination 1",
            package_type="Delivery",
            item_description="Test Item 1",
            item_weight="medium",
            receiver_name="Receiver 1",
            receiver_phone_number="1234567890"
        )

        # Create a test package for user2 (no bids will be placed on this one)
        self.package2 = Package.objects.create(
            user=self.user2,
            location="Test Location 2",
            destination="Test Destination 2",
            package_type="Delivery",
            item_description="Test Item 2",
            item_weight="medium",
            receiver_name="Receiver 2",
            receiver_phone_number="0987654321"
        )

        # Create a bid on package1 by user1
        self.token_user1 = Token.objects.create(user=self.user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user1.key}')
        self.bid1 = Bid.objects.create(
            package=self.package1,
            mover=self.user1,
            price=100.00
        )

        # Define the URLs for GetAllBidsView endpoint
        self.url_user1 = reverse('get-all-bids', kwargs={'package_id': self.package1.id})
        self.url_user2 = reverse('get-all-bids', kwargs={'package_id': self.package2.id})

    def tearDown(self):
        """
        Clean up any created data after tests are run.
        """
        self.package1.delete()
        self.package2.delete()
        self.user1.delete()
        self.user2.delete()

    def test_get_bids_as_package_owner(self):
        """
        Test retrieving bids for a package as the package owner.
        """
        # Send GET request as user1 (owner of package1)
        response = self.client.get(self.url_user1)

        # Assert the response status code and bid data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # One bid placed by user1
        self.assertEqual(response.data[0]['id'], self.bid1.id)
        self.assertEqual(response.data[0]['price'], '100.00')

    def test_get_bids_as_non_owner(self):
        """
        Test retrieving bids for a package as a non-owner.
        """
        # Authenticate as user2 (not the owner of package1)
        self.token_user2 = Token.objects.create(user=self.user2)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user2.key}')

        # Send GET request as user2 (non-owner of package1)
        response = self.client.get(self.url_user1)

        # Assert the response status code and error message
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data, {"error": "You are not authorized to view the bids for this package."})

    def test_get_bids_for_non_existing_package(self):
        """
        Test retrieving bids for a non-existing package.
        """
        # Use a non-existing package_id (assume 99999 doesn't exist)
        invalid_url = reverse('get-all-bids', kwargs={'package_id': 99999})

        # Send GET request with an invalid package ID
        response = self.client.get(invalid_url)

        # Assert the response status code and error message
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data, {"error": "Package not found."})

    def test_get_bids_for_package_with_no_bids(self):
        """
        Test retrieving bids for a package that has no bids.
        """
        # Send GET request as user2 (owner of package2, which has no bids)
        self.token_user2 = Token.objects.create(user=self.user2)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user2.key}')
        response = self.client.get(self.url_user2)

        # Assert the response status code and empty bid list
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, [])  # No bids available for package2


class GetBidDetailViewTest(APITestCase):
    """
    Test case for retrieving details of a specific bid.
    """

    def setUp(self):
        """
        Setup the test environment by creating two users, authenticating them,
        creating packages, and placing bids for the tests.
        """
        # Create test users
        self.user1 = CustomUser.objects.create_user(email='user1@example.com', password='password123')
        self.user2 = CustomUser.objects.create_user(email='user2@example.com', password='password123')

        # Create a test package for user1
        self.package1 = Package.objects.create(
            user=self.user1,
            location="Test Location 1",
            destination="Test Destination 1",
            package_type="Delivery",
            item_description="Test Item 1",
            item_weight="medium",
            receiver_name="Receiver 1",
            receiver_phone_number="1234567890"
        )

        # Create a bid on package1 by user1
        self.token_user1 = Token.objects.create(user=self.user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user1.key}')
        self.bid1 = Bid.objects.create(
            package=self.package1,
            mover=self.user1,
            price=100.00
        )

        # Create a bid on package1 by user2 (user2 is a different mover)
        self.token_user2 = Token.objects.create(user=self.user2)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user2.key}')
        self.bid2 = Bid.objects.create(
            package=self.package1,
            mover=self.user2,
            price=150.00
        )

        # Define the URLs for GetBidDetailView endpoint
        self.url_bid1 = reverse('get-bid-detail', kwargs={'bid_id': self.bid1.id})
        self.url_bid2 = reverse('get-bid-detail', kwargs={'bid_id': self.bid2.id})

    def tearDown(self):
        """
        Clean up any created data after tests are run.
        """
        self.package1.delete()
        self.user1.delete()
        self.user2.delete()

    def test_get_bid_detail_as_owner(self):
        """
        Test retrieving bid details as the owner of the package.
        """
        # Authenticate as user1 (owner of package1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user1.key}')

        # Send GET request to view the bid placed by user1
        response = self.client.get(self.url_bid1)

        # Assert the response status code and bid data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['id'], self.bid1.id)
        self.assertEqual(response.data['price'], '100.00')

    def test_get_bid_detail_as_mover(self):
        """
        Test retrieving bid details as the mover who placed the bid.
        """
        # Authenticate as user2 (mover of bid2)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user2.key}')

        # Send GET request to view the bid placed by user2
        response = self.client.get(self.url_bid2)

        # Assert the response status code and bid data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['id'], self.bid2.id)
        self.assertEqual(response.data['price'], '150.00')

    def test_get_bid_detail_as_non_owner_and_non_mover(self):
        """
        Test retrieving bid details as a user who is neither the owner of the package nor the mover.
        """
        # Authenticate as a different user (user2)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user2.key}')

        # Send GET request as user2 (not the owner of the package or the mover for bid1)
        response = self.client.get(self.url_bid1)

        # Assert the response status code and error message
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data, {"error": "You are not authorized to view this bid."})

    def test_get_bid_detail_for_non_existing_bid(self):
        """
        Test retrieving bid details for a non-existing bid.
        """
        # Use a non-existing bid_id (assume 99999 doesn't exist)
        invalid_url = reverse('get-bid-detail', kwargs={'bid_id': 99999})

        # Send GET request with an invalid bid ID
        response = self.client.get(invalid_url)

        # Assert the response status code and error message
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data, {"error": "Bid not found."})


class SelectMoverViewTests(APITestCase):
    def setUp(self):
        # Set up users, bids, and packages here
        self.user1 = CustomUser.objects.create_user(email='user1@example.com', password='password')
        self.user2 = CustomUser.objects.create_user(email='user2@example.com', password='password')
        self.package = Package.objects.create(user=self.user1, location="Location A", destination="Location B")
        self.bid = Bid.objects.create(package=self.package, mover=self.user2, price="100.00")

        # Create token for user1 and user2
        self.token_user1 = Token.objects.create(user=self.user1)
        self.token_user2 = Token.objects.create(user=self.user2)

        self.url = reverse('select-mover', args=[self.bid.id])

    def tearDown(self):
        """
        Clean up any resources after each test case runs.
        """
        # Deleting objects to clean up after tests
        try:
            self.user1.delete()
            self.user2.delete()
            self.package.delete()
            self.bid.delete()
            QRCode.objects.all().delete()
            PackageOffer.objects.all().delete()
        except Exception as e:
            print(f"Error during teardown: {e}")

    def test_select_mover_as_owner(self):
        # Authenticate as the package owner (user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user1.key}')
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('has been selected for the delivery', response.data['message'])

    def test_select_mover_as_mover(self):
        # Authenticate as the mover (user2)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user2.key}')
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('has been selected for the delivery', response.data['message'])

    def test_select_mover_as_unauthorized_user(self):
        # Authenticate as an unauthorized user (user3)
        user3 = CustomUser.objects.create_user(email='user3@example.com', password='password')
        token_user3 = Token.objects.create(user=user3)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token_user3.key}')
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['error'], 'You are not authorized to select a mover for this package.')

    def test_bid_already_selected(self):
        # Simulate a case where the mover has already been selected
        qr_code = QRCode.objects.create()
        PackageOffer.objects.create(package_bid=self.bid, qr_code=qr_code)

        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user1.key}')
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Mover has already been selected for this bid.')


class GetPackageOfferDetailViewTests(APITestCase):
    def setUp(self):
        """
        Set up the necessary objects for the test.
        """
        self.user1 = CustomUser.objects.create_user(email='user1@example.com', password='password')
        self.user2 = CustomUser.objects.create_user(email='user2@example.com', password='password')

        # Create package for user1
        self.package = Package.objects.create(user=self.user1, location="Location A", destination="Location B")

        # Create bid for the package
        self.bid = Bid.objects.create(package=self.package, mover=self.user2, price="100.00")

        # Create a QRCode and PackageOffer for the bid
        qr_code = QRCode.objects.create()
        self.package_offer = PackageOffer.objects.create(package_bid=self.bid, qr_code=qr_code)

        # Create token for user1 (package owner)
        self.token_user1 = Token.objects.create(user=self.user1)
        # Create token for user2 (mover who placed the bid)
        self.token_user2 = Token.objects.create(user=self.user2)

        # URL for the view
        self.url = reverse('get-package-offer-detail', args=[self.package_offer.id])

    def tearDown(self):
        """
        Clean up after each test case runs.
        """
        try:
            self.user1.delete()
            self.user2.delete()
            self.package.delete()
            self.bid.delete()
            self.package_offer.delete()
            QRCode.objects.all().delete()
        except Exception as e:
            print(f"Error during teardown: {e}")

    def test_get_package_offer_detail_as_owner(self):
        """
        Test retrieving the package offer details as the package owner (user1).
        """
        # Authenticate as user1 (owner of the package)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user1.key}')
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['id'], self.package_offer.id)
        self.assertEqual(response.data['package_bid'], self.bid.id)

    def test_get_package_offer_detail_as_mover(self):
        """
        Test retrieving the package offer details as the mover (user2).
        """
        # Authenticate as user2 (the mover who placed the bid)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user2.key}')
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['id'], self.package_offer.id)
        self.assertEqual(response.data['package_bid'], self.bid.id)

    def test_get_package_offer_detail_as_unauthorized_user(self):
        """
        Test that a user who is not authorized (neither owner nor mover) cannot access the package offer details.
        """
        # Create a third user
        user3 = CustomUser.objects.create_user(email='user3@example.com', password='password')
        token_user3 = Token.objects.create(user=user3)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_package_offer_detail_package_offer_not_found(self):
        """
        Test retrieving package offer details for a non-existent package offer.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user2.key}')
        # Send GET request with a non-existent package_offer_id
        response = self.client.get(reverse('get-package-offer-detail', args=[99999]))  # Non-existent ID

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['error'], "Package offer not found.")


class PickupConfirmationViewTests(APITestCase):
    def setUp(self):
        """
        Set up the necessary objects for the test.
        """
        self.user1 = CustomUser.objects.create_user(email='user1@example.com', password='password')
        self.user2 = CustomUser.objects.create_user(email='user2@example.com', password='password')

        # Create package for user1
        self.package = Package.objects.create(user=self.user1, location="Location A", destination="Location B")

        # Create bid for the package
        self.bid = Bid.objects.create(package=self.package, mover=self.user2, price="100.00")

        # Create a QRCode and PackageOffer for the bid
        self.qr_code = QRCode.objects.create(code="12345")  # Use an example code
        self.package_offer = PackageOffer.objects.create(package_bid=self.bid, qr_code=self.qr_code)

        # Create token for user1 (package owner)
        self.token_user1 = Token.objects.create(user=self.user1)
        # Create token for user2 (mover who placed the bid)
        self.token_user2 = Token.objects.create(user=self.user2)

        # URL for the view
        self.url = reverse('confirm-pickup', args=[self.package_offer.id])

    def tearDown(self):
        """
        Clean up after each test case runs.
        """
        try:
            self.user1.delete()
            self.user2.delete()
            self.package.delete()
            self.bid.delete()
            self.package_offer.delete()
            self.qr_code.delete()
        except Exception as e:
            print(f"Error during teardown: {e}")

    def test_pickup_confirmation_valid_code(self):
        """
        Test confirming pickup with a valid QR code.
        """
        # Authenticate as user2 (mover)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user2.key}')
        response = self.client.post(self.url, {'code': '12345'})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], "Pickup confirmed.")
        self.package_offer.refresh_from_db()
        self.assertTrue(self.package_offer.is_picked_up)

    def test_pickup_confirmation_invalid_code(self):
        """
        Test attempting to confirm pickup with an invalid QR code.
        """
        # Authenticate as user2 (mover)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user2.key}')
        response = self.client.post(self.url, {'code': 'wrongcode'})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], "Invalid code.")

    def test_pickup_confirmation_unauthorized_user(self):
        """
        Test that an unauthorized user (not the mover or package owner) cannot confirm the pickup.
        """
        response = self.client.post(self.url, {'code': '12345'})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class DeliveryConfirmationViewTests(APITestCase):
    def setUp(self):
        """
        Set up the necessary objects for the test.
        """
        self.user1 = CustomUser.objects.create_user(email='user1@example.com', password='password')
        self.user2 = CustomUser.objects.create_user(email='user2@example.com', password='password')

        # Create package for user1
        self.package = Package.objects.create(user=self.user1, location="Location A", destination="Location B")

        # Create bid for the package
        self.bid = Bid.objects.create(package=self.package, mover=self.user2, price="100.00")

        # Create a QRCode and PackageOffer for the bid
        self.qr_code = QRCode.objects.create(code="12345")  # Example code
        self.package_offer = PackageOffer.objects.create(package_bid=self.bid, qr_code=self.qr_code)

        # Create token for user1 (package owner)
        self.token_user1 = Token.objects.create(user=self.user1)
        # Create token for user2 (mover who placed the bid)
        self.token_user2 = Token.objects.create(user=self.user2)

        # URL for the view
        self.url = reverse('confirm-delivery', args=[self.package_offer.id])

    def tearDown(self):
        """
        Clean up after each test case runs.
        """
        try:
            self.user1.delete()
            self.user2.delete()
            self.package.delete()
            self.bid.delete()
            self.package_offer.delete()
            self.qr_code.delete()
        except Exception as e:
            print(f"Error during teardown: {e}")

    def test_delivery_confirmation_valid_code(self):
        """
        Test confirming delivery with a valid QR code.
        """
        # Authenticate as user2 (mover)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user2.key}')
        response = self.client.post(self.url, {'code': '12345'})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], "Delivery confirmed.")
        self.package_offer.refresh_from_db()
        self.assertTrue(self.package_offer.is_delivered)

    def test_delivery_confirmation_invalid_code(self):
        """
        Test attempting to confirm delivery with an invalid QR code.
        """
        # Authenticate as user2 (mover)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_user2.key}')
        response = self.client.post(self.url, {'code': 'wrongcode'})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], "Invalid code.")

def test_delivery_confirmation_unauthorized_user(self):
        """
        Test that an unauthorized user (not the mover or package owner) cannot confirm the delivery.
        """
        response = self.client.post(self.url, {'code': '12345'})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class ProfileImageUploadViewTestCase(APITestCase):
    """
    Test cases for the ProfileImageUploadView API view.
    """

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('upload-profile-image')
        
        # Create a test user and token
        self.user = CustomUser.objects.create_user(
            email="testuser@example.com",
            password="password123",
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def tearDown(self):
        return super().tearDown()

    def test_successful_profile_image_upload(self):
        """
        Test that a valid profile image upload is successful.
        """
        # Create a temporary image file
        image = Image.new('RGB', (100, 100), 'red')
        image_file = BytesIO()
        image.save(image_file, 'jpeg')
        image_file.seek(0)
        
        # Upload the image
        response = self.client.post(
            self.url,
            {'profile_picture': SimpleUploadedFile(
                'test_image.jpg',
                image_file.getvalue(),
                content_type='image/jpeg'
            )},
            format='multipart'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertEqual(response.data['message'], 'Profile picture uploaded successfully.')
        self.assertIn('user', response.data)
        
        # Verify the user's profile picture was updated
        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.profile_picture)
        self.assertTrue(self.user.profile_picture.name.endswith('.jpg'))

    def test_profile_image_upload_missing_file(self):
        """
        Test that upload fails when no profile picture is provided.
        """
        response = self.client.post(self.url, {}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Profile picture is required.')

    def test_profile_image_upload_invalid_file_type(self):
        """
        Test that upload fails when file is not an image.
        """
        # Upload a text file instead of image
        response = self.client.post(
            self.url,
            {'profile_picture': SimpleUploadedFile(
                'test_file.txt',
                b'This is not an image',
                content_type='text/plain'
            )},
            format='multipart'
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Profile picture must be a valid image file.')

    def test_profile_image_upload_file_too_large(self):
        """
        Test that upload fails when file size exceeds 5MB limit.
        """
        # Create a file larger than 5MB (6MB of dummy data)
        large_file_content = b'x' * (6 * 1024 * 1024)  # 6MB of 'x' characters
        
        response = self.client.post(
            self.url,
            {'profile_picture': SimpleUploadedFile(
                'large_file.jpg',
                large_file_content,
                content_type='image/jpeg'
            )},
            format='multipart'
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Profile picture size must be under 5MB.')

    def test_profile_image_upload_unauthorized(self):
        """
        Test that unauthorized users cannot upload profile images.
        """
        # Remove authentication
        self.client.credentials()
        
        image = Image.new('RGB', (100, 100), 'red')
        image_file = BytesIO()
        image.save(image_file, 'jpeg')
        image_file.seek(0)
        
        response = self.client.post(
            self.url,
            {'profile_picture': SimpleUploadedFile(
                'test_image.jpg',
                image_file.getvalue(),
                content_type='image/jpeg'
            )},
            format='multipart'
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
