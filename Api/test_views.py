from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import status
from rest_framework.test import APIClient, APITestCase
from django.test import TestCase

import unittest
from unittest.mock import patch, Mock

from django.test import RequestFactory
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed

from Api.models import CustomUser, KYC, Vehicle, Subscription, OTP, SocialMediaLink, SubscriptionPlan
from Api.views import get_user_from_token


# class GetUserFromTokenTestCase(unittest.TestCase):
#     def setUp(self):
#         self.factory = RequestFactory()
#
#     def test_get_user_from_token_deactivated_user(self):
#         # Create a deactivated user and associated token
#         user = CustomUser.objects.create_user(email='deactivated1@example.com', password='password')
#         user.is_active = False
#         token = Token.objects.create(user=user)
#
#         # Create a request with the token in the Authorization header
#         request = self.factory.get('/some-url', HTTP_AUTHORIZATION=f'Token {token.key}')
#         request.headers = {'Authorization': 'Token invalidtoken123'}
#
#         # Assert that AuthenticationFailed is raised when trying to get a user from a token of a deactivated user
#         with self.assertRaises(AuthenticationFailed):
#             get_user_from_token(request)
#
#         # Clean up
#         token.delete()
#         user.delete()
#
#     def test_should_raise_authentication_failed_with_multiple_tokens(self):
#         request = self.factory.get('/')
#         request.headers = {'Authorization': 'Token token1 token2'}
#
#         with self.assertRaises(AuthenticationFailed) as context:
#             get_user_from_token(request)
#
#         self.assertEqual(str(context.exception), 'Invalid token')
#
#
#     def test_get_user_from_token_invalid_token(self):
#         request = self.factory.get('/')
#         request.headers = {'Authorization': 'Token invalidtoken123'}
#
#         with self.assertRaises(AuthenticationFailed) as context:
#             get_user_from_token(request)
#
#         self.assertEqual(str(context.exception), 'Invalid token')
#
#     def test_should_raise_authentication_failed_when_authorization_header_is_empty(self):
#         request = self.factory.get('/some-url', HTTP_AUTHORIZATION='')
#         request.headers = {'Authorization': 'Token invalidtoken123'}
#         with self.assertRaises(AuthenticationFailed) as context:
#             get_user_from_token(request)
#         self.assertEqual(str(context.exception), 'Invalid token')
#
#     def test_get_user_from_token_malformed_token(self):
#         request = self.factory.get('/some-url', HTTP_AUTHORIZATION='Bearer malformedtoken')
#         request.headers = {'Authorization': 'Token invalidtoken123'}
#         with self.assertRaises(AuthenticationFailed) as context:
#             get_user_from_token(request)
#         self.assertEqual(str(context.exception), 'Invalid token')
#
#     def test_should_raise_authentication_failed_when_authorization_header_is_missing(self):
#         request = self.factory.get('/')
#         request.headers = {}
#         with self.assertRaises(AuthenticationFailed) as context:
#             get_user_from_token(request)
#         self.assertEqual(str(context.exception), 'Invalid token')
#
#     def test_get_user_from_token_expired_token(self):
#         request = self.factory.get('/')
#         request.headers = {'Authorization': 'Token expired_token_key'}
#
#         with patch('Api.views.Token.objects.get') as mock_get:
#             mock_get.side_effect = Token.DoesNotExist
#             with self.assertRaises(AuthenticationFailed) as context:
#                 get_user_from_token(request)
#
#             self.assertEqual(str(context.exception), 'Invalid token')
#
#     def test_get_user_from_token_case_insensitive_authorization_header(self):
#         # Create a mock request with a case-insensitive 'Authorization' header
#         request = self.factory.get('/')
#         request.headers = {'Authorization': 'Token testtoken123'}
#
#         # Create a mock token and user
#         user = CustomUser.objects.create_user(
#             email='testuser2@example.com',
#             password='testpassword',
#             is_email_verified=True
#         )
#         token = Token.objects.create(user=user)
#
#         # Call the function and assert the user is returned correctly
#         result_user = get_user_from_token(request)
#         self.assertEqual(result_user, user)
#
#         # Clean up
#         token.delete()
#         user.delete()
#
#     def test_get_user_from_token_valid_token(self):
#         # Create a user and a token for that user
#         user = CustomUser.objects.create_user(email='testuser1@example.com', password='testpass')
#         token = Token.objects.create(user=user)
#
#         # Create a request with the token in the Authorization header
#         request = self.factory.get('/')
#         request.headers = {'Authorization': f'Token {token.key}'}
#
#         # Call the function and assert the returned user is correct
#         returned_user = get_user_from_token(request)
#         self.assertEqual(returned_user, user)
#
#         # Clean up
#         token.delete()
#         user.delete()


@pytest.mark.django_db
class TestRegisterView:
    def setup_method(self):
        self.client = APIClient()
        self.url = reverse('register')

    def test_register_view_handles_exceptions_gracefully(self, mocker):
        # Mock the serializer to be valid
        mock_serializer = mocker.patch('path.to.CustomUserSerializer')
        mock_serializer.return_value.is_valid.return_value = True
        mock_serializer.return_value.validated_data = {'email': 'test@example.com'}

        # Mock the CustomUser.objects.create to raise an exception
        mock_create_user = mocker.patch('path.to.CustomUser.objects.create')
        mock_create_user.side_effect = Exception('Database error')

        response = self.client.post(self.url, data={'email': 'test@example.com', 'password': 'password123'})

        assert response.status_code == 500
        assert response.data == {'error': 'Database error'}

    def test_register_view_returns_500_on_exception(mocker):
        client = APIClient()
        url = reverse('register')
        mocker.patch('Api.views.CustomUser.objects.create', side_effect=Exception("Test Exception"))

        response = client.post(url, {'email': 'test@example.com', 'password': 'password123'})

        assert response.status_code == 500
        assert response.data == {'error': 'Test Exception'}

    def test_register_view_invalid_email_format(self):
        # Arrange
        invalid_email_data = {
            'email': 'invalid-email-format',
            'password': 'validpassword123'
        }

        # Act
        response = self.client.post(self.url, invalid_email_data, format='json')

        # Assert
        assert response.status_code == 400
        assert 'email' in response.data
        assert response.data['email'] == ['Enter a valid email address.']

    def test_register_view_missing_email(self):
        response = self.client.post(self.url, data={'password': 'testpassword123'})
        assert response.status_code == 400
        assert 'email' in response.data

    def test_register_view_missing_password(self):
        response = self.client.post(self.url, {'email': 'test@example.com'})
        assert response.status_code == 400
        assert 'password' in response.data

    def test_register_view_invalid_serializer_data(self):
        # Arrange
        invalid_data = {
            'email': 'invalid-email',  # Invalid email format
            'password': 'short'  # Password too short
        }

        # Act
        response = self.client.post(self.url, invalid_data, format='json')

        # Assert
        assert response.status_code == 400
        assert 'email' in response.data or 'password' in response.data

    def test_should_send_otp_for_email_verification_upon_successful_registration(mocker):
        # Arrange
        client = APIClient()
        url = reverse('register')
        user_data = {
            'email': 'testuser@example.com',
            'password': 'securepassword123'
        }
        mock_otp_send = mocker.patch('path.to.OTP.send_otp')  # Mock the send_otp method

        # Act
        response = client.post(url, data=user_data, format='json')

        # Assert
        assert response.status_code == 200
        assert mock_otp_send.called

    def test_register_creates_kyc_vehicle_subscription(self, mocker):
        # Mock the OTP send_otp method to prevent actual email sending
        mocker.patch('path.to.OTP.send_otp', return_value=None)

        # Prepare the registration data
        registration_data = {
            'email': 'testuser@example.com',
            'password': 'securepassword123'
        }

        # Send a POST request to the registration endpoint
        response = self.client.post(self.url, registration_data)

        # Assert that the response status is 200 OK
        assert response.status_code == 200

        # Retrieve the created user
        user = CustomUser.objects.get(email='testuser@example.com')

        # Assert that the KYC, Vehicle, and Subscription objects are created
        assert KYC.objects.filter(user=user).exists()
        assert Vehicle.objects.filter(user=user).exists()
        assert Subscription.objects.filter(user=user, plan__name='free').exists()

    def test_register_user_successfully(self):
        # Arrange
        valid_data = {
            'email': 'testuser@example.com',
            'password': 'securepassword123'
        }

        # Act
        response = self.client.post(self.url, data=valid_data)

        # Assert
        assert response.status_code == 200
        assert 'email' in response.data
        assert response.data['email'] == valid_data['email']
        assert CustomUser.objects.filter(email=valid_data['email']).exists()

    def test_register_view_rate_limiting(self):
        for _ in range(5):
            response = self.client.post(self.url, {'email': 'test@example.com', 'password': 'testpassword'})
            assert response.status_code != 429  # Ensure not rate limited before 5 attempts

        # Sixth attempt should be rate limited
        response = self.client.post(self.url, {'email': 'test@example.com', 'password': 'testpassword'})
        assert response.status_code == 429  # Rate limit status code


# @pytest.mark.django_db
# class TestVerifyOTPView:
#     def setup_method(self):
#         self.client = APIClient()
#         self.url = reverse('verify-otp')
#
#     def test_verify_otp_invalid_email(self):
#         # Arrange
#         data = {
#             'email': 'nonexistent@example.com',
#             'code': '123456'
#         }
#
#         # Act
#         response = self.client.post(self.url, data)
#
#         # Assert
#         assert response.status_code == 400
#         assert response.data == {'error': 'Invalid OTP'}
#
#     def test_should_return_invalid_otp_error_when_otp_does_not_exist(self):
#         response = self.client.post(self.url, {'email': 'test@example.com', 'code': '123456'})
#         assert response.status_code == 400
#         assert response.data == {'error': 'Invalid OTP'}
#
#     def test_verify_otp_invalid_code(self, mocker):
#         # Arrange
#         mocker.patch('Api.views.OTP.objects.get', side_effect=OTP.DoesNotExist)
#         data = {'email': 'test@example.com', 'code': 'invalid_code'}
#
#         # Act
#         response = self.client.post(self.url, data=data)
#
#         # Assert
#         assert response.status_code == 400
#         assert response.data == {'error': 'Invalid OTP'}
#
#     def test_should_not_verify_email_if_otp_expired(self, mocker):
#         # Mock the OTPVerificationSerializer to return valid data
#         serializer_mock = mocker.patch('path.to.OTPVerificationSerializer')
#         serializer_mock.return_value.is_valid.return_value = True
#         serializer_mock.return_value.validated_data = {'email': 'test@example.com', 'code': '123456'}
#
#         # Mock the OTP object to simulate an expired OTP
#         otp_mock = mocker.patch('path.to.OTP.objects.get')
#         otp_instance = otp_mock.return_value
#         otp_instance.is_expired.return_value = True
#
#         response = self.client.post(self.url, {'email': 'test@example.com', 'code': '123456'})
#
#         assert response.status_code == 400
#         assert response.data == {'error': 'OTP has expired'}
#
#     def test_should_return_otp_has_expired_error_when_otp_is_expired(self, mocker):
#         # Arrange
#         expired_otp = mocker.Mock()
#         expired_otp.is_used = False
#         expired_otp.is_expired.return_value = True
#
#         mocker.patch('Api.views.OTP.objects.get', return_value=expired_otp)
#
#         data = {
#             'email': 'test@example.com',
#             'code': '123456'
#         }
#
#         # Act
#         response = self.client.post(self.url, data, format='json')
#
#         # Assert
#         assert response.status_code == 400
#         assert response.data['error'] == 'OTP has expired'
#
#     def test_verify_otp_success(mocker):
#         # Arrange
#         client = APIClient()
#         url = reverse('verify-otp')
#         email = 'test@example.com'
#         code = '123456'
#
#         # Mock the OTP object
#         mock_otp = mocker.Mock()
#         mock_otp.is_used = False
#         mock_otp.is_expired.return_value = False
#         mock_otp.user.is_email_verified = False
#
#         # Mock the OTP.objects.get method
#         mocker.patch('Api.views.OTP.objects.get', return_value=mock_otp)
#
#         # Act
#         response = client.post(url, {'email': email, 'code': code}, format='json')
#
#         # Assert
#         assert response.status_code == 200
#         assert response.data == {'message': 'Email verified successfully'}
#         assert mock_otp.is_used is True
#         assert mock_otp.user.is_email_verified is True
#
#     def test_should_return_error_when_otp_already_used(self, mocker):
#         # Arrange
#         data = {
#             'email': 'test@example.com',
#             'code': '123456'
#         }
#         otp_mock = mocker.Mock()
#         otp_mock.is_used = True
#         mocker.patch('Api.views.OTP.objects.get', return_value=otp_mock)
#         serializer_mock = mocker.patch('Api.views.OTPVerificationSerializer')
#         serializer_mock.return_value.is_valid.return_value = True
#         serializer_mock.return_value.validated_data = data
#
#         # Act
#         response = self.client.post(self.url, data)
#
#         # Assert
#         assert response.status_code == 400
#         assert response.data == {'error': 'OTP has already been used'}
#
#     def test_verify_otp_view_missing_required_fields(self):
#         response = self.client.post(self.url, data={})
#         assert response.status_code == 400
#         assert 'email' in response.data
#         assert 'code' in response.data
#
#     def test_rate_limiting_blocks_after_exceeding_limit(self):
#         # Simulate 5 successful requests
#         for _ in range(5):
#             response = self.client.post(self.url, {'email': 'test@example.com', 'code': '123456'})
#             assert response.status_code != 429  # Ensure no rate limit error on first 5 requests
#
#         # Simulate the 6th request which should be blocked
#         response = self.client.post(self.url, {'email': 'test@example.com', 'code': '123456'})
#         assert response.status_code == 429  # Ensure rate limit error on 6th request
#
#     def test_verify_otp_concurrent_requests(db, mocker):
#         from django.contrib.auth import get_user_model
#         from Api.models import OTP
#         from rest_framework.test import APIClient
#         from django.urls import reverse
#         from threading import Thread
#
#         User = get_user_model()
#         user = User.objects.create_user(email='test@example.com', password='testpass')
#         otp = OTP.objects.create(user=user, code='123456', is_used=False)
#
#         client = APIClient()
#         url = reverse('verify-otp')
#         data = {'email': 'test@example.com', 'code': '123456'}
#
#         def make_request():
#             response = client.post(url, data)
#             assert response.status_code == 200
#             assert response.data['message'] == 'Email verified successfully'
#
#         # Simulate concurrent requests
#         threads = [Thread(target=make_request) for _ in range(5)]
#         for thread in threads:
#             thread.start()
#         for thread in threads:
#             thread.join()
#
#         # Ensure OTP is marked as used only once
#         otp.refresh_from_db()
#         assert otp.is_used
#         assert user.is_email_verified


# class LoginViewTest(TestCase):
#     def setUp(self):
#         self.client = APIClient()
#         self.login_url = reverse('login')
#         self.logout_url = reverse('logout')
#         self.user = CustomUser.objects.create_user(
#             email='testuser@example.com',
#             password='testpassword',
#             is_email_verified=True
#         )
#         self.token = Token.objects.create(user=self.user)
#
#     def test_login_case_insensitivity(self):
#         # Create a user with a known email and password
#         user_email = 'TestUser@Example.com'
#         user_password = 'testpassword'
#         user = CustomUser.objects.create_user(
#             email=user_email,
#             password=user_password,
#             is_email_verified=True
#         )
#         Token.objects.create(user=user)
#
#         # Attempt to login with a different case in the email
#         response = self.client.post(self.login_url, {
#             'email': 'testuser@example.com',  # Lowercase email
#             'password': user_password
#         })
#
#         # Check that the response is successful and contains a token
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertIn('token', response.data)
#
#     def test_should_return_new_token_on_relogin(self):
#         # Log in once to generate a token
#         response1 = self.client.post(self.login_url, {'email': 'testuser@example.com', 'password': 'testpassword'})
#         token1 = response1.data['token']['key']
#
#         self.client.post(self.logout_url)
#
#         # Log in again to generate a new token
#         response2 = self.client.post(self.login_url, {'email': 'testuser@example.com', 'password': 'testpassword'})
#         token2 = response2.data['token']['key']
#
#         # Assert that a new token is generated
#         self.assertNotEqual(token1, token2)
#         self.assertEqual(response2.status_code, 200)
#
#     def test_successful_authentication_with_verified_email(self):
#         response = self.client.post(self.login_url, {
#             'email': 'testuser@example.com',
#             'password': 'testpassword'
#         })
#         self.assertEqual(response.status_code, 200)
#         self.assertIn('token', response.data)
#         self.assertIn('user', response.data)
#         self.assertEqual(response.data['user']['email'], 'testuser@example.com')
#
#     def test_login_unverified_email(self):
#         # Create a user with an unverified email
#         unverified_user = CustomUser.objects.create_user(
#             email='unverified@example.com',
#             password='testpassword',
#             is_email_verified=False
#         )
#
#         # Attempt to log in with the unverified user's credentials
#         response = self.client.post(self.login_url, {
#             'email': 'unverified@example.com',
#             'password': 'testpassword'
#         })
#
#         # Check that the response contains the correct error message
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
#         self.assertEqual(response.data['error'], 'Email is not verified')
#
#     def test_login_with_non_existent_email(self):
#         response = self.client.post(self.login_url, {'email': 'nonexistent@example.com', 'password': 'any_password'})
#         self.assertEqual(response.status_code, 400)
#         self.assertEqual(response.data['error'], 'Invalid email or phone number')
#
#     def test_login_without_email(self):
#         # Prepare the request data without email
#         data = {
#             'password': 'testpassword'
#         }
#
#         # Make a POST request to the login endpoint
#         response = self.client.post(self.login_url, data, format='json')
#
#         # Assert that the response status code is 400 Bad Request
#         self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
#
#         # Assert that the error message is about the missing email
#         self.assertEqual(response.data['error'], 'Invalid email or phone number')
#
#     def test_login_without_password(self):
#         response = self.client.post(self.login_url, {'email': 'testuser@example.com'})
#         self.assertEqual(response.status_code, 403)
#         self.assertEqual(response.data['error'], 'Invalid credentials')
#
#     def test_login_invalid_password(self):
#         response = self.client.post(self.login_url, {'email': 'testuser@example.com', 'password': 'wrongpassword'})
#         self.assertEqual(response.status_code, 400)
#         self.assertEqual(response.data['error'], 'Invalid credentials')
#
#     def test_login_with_invalid_email_format(self):
#         response = self.client.post(self.login_url, {'email': 'invalid-email-format', 'password': 'testpassword'})
#         self.assertEqual(response.status_code, 400)
#         self.assertEqual(response.data['error'], 'Invalid email or phone number')
#
#     def test_rate_limiting_on_failed_login_attempts(self):
#         # Simulate 5 failed login attempts
#         for _ in range(5):
#             response = self.client.post(self.login_url,
#                                         {'email': 'wrongemail@example.com', 'password': 'wrongpassword'})
#             self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
#             self.assertEqual(response.data['error'], 'Invalid email or phone number')
#
#         # 6th attempt should be blocked due to rate limiting
#         response = self.client.post(self.login_url, {'email': 'wrongemail@example.com', 'password': 'wrongpassword'})
#         self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)


# @pytest.mark.django_db
# class TestLogoutView:
#
#     @pytest.fixture
#     def api_client(self):
#         return APIClient()
#
#     @pytest.fixture
#     def user_with_token(self):
#         User = get_user_model()
#         user = User.objects.create_user(email='testuser@example.com', password='password123')
#         token, _ = Token.objects.get_or_create(user=user)
#         return user, token
#
#     def test_logout_view_server_error(self, api_client, user_with_token, mocker):
#         user, token = user_with_token
#         api_client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
#
#         # Mock the Token.objects.get method to raise an exception
#         mocker.patch('rest_framework.authtoken.models.Token.objects.get', side_effect=Exception("Server error"))
#
#         response = api_client.post('/api/logout/')
#
#         assert response.status_code == 500
#         assert response.data['detail'] == "Server error"
#
#     def test_logout_view_success(api_client, user_with_token):
#         user, token = user_with_token
#         api_client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
#
#         response = api_client.post('/api/logout/')
#
#         assert response.status_code == 200
#         assert response.data['detail'] == "Successfully logged out."
#
#     def test_logout_view_success(api_client, user_with_token):
#         user, token = user_with_token
#         api_client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
#
#         response = api_client.post('/api/logout/')
#
#         assert response.status_code == 200
#         assert response.data['detail'] == "Successfully logged out."
#
#     @pytest.mark.django_db
#     def test_concurrent_logout_requests(api_client, user_with_token):
#         user, token = user_with_token
#         api_client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
#
#         # Simulate two concurrent logout requests
#         response1 = api_client.post('/logout/')
#         response2 = api_client.post('/logout/')
#
#         # Check that the first request logs out the user successfully
#         assert response1.status_code == status.HTTP_200_OK
#         assert response1.data['detail'] == "Successfully logged out."
#
#         # Check that the second request fails because the user is already logged out
#         assert response2.status_code == status.HTTP_400_BAD_REQUEST
#         assert response2.data['detail'] == "Invalid token or user already logged out."
#
#     def test_logout_with_expired_token(self, api_client, user_with_token, mocker):
#         user, token = user_with_token
#         # Mock the token expiration check to simulate an expired token
#         mocker.patch('rest_framework.authtoken.models.Token.objects.get', side_effect=Token.DoesNotExist)
#
#         # Set the token in the Authorization header
#         api_client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
#
#         # Make a POST request to the logout endpoint
#         response = api_client.post('/logout/')
#
#         # Assert the response status code and message
#         assert response.status_code == 400
#         assert response.data['detail'] == "Invalid token or user already logged out."
#
#     def test_logout_view_no_token_deletion(api_client, user_with_token, mocker):
#         user, token = user_with_token
#         api_client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
#
#         # Mock the Token.objects.get method to simulate token not existing
#         mocker.patch('rest_framework.authtoken.models.Token.objects.get', side_effect=Token.DoesNotExist)
#
#         response = api_client.post('/api/logout/')
#
#         assert response.status_code == 400
#         assert response.data['detail'] == "Invalid token or user already logged out."
#
#     def test_logout_view_invalid_token(self, api_client):
#         # Arrange
#         invalid_token = 'InvalidToken123'
#         api_client.credentials(HTTP_AUTHORIZATION=f'Token {invalid_token}')
#
#         # Act
#         response = api_client.post('/api/logout/')
#
#         # Assert
#         assert response.status_code == 400
#         assert response.data == {"detail": "Invalid token or user already logged out."}
#
#     def test_logout_invalid_token(api_client):
#         # Attempt to logout with an invalid token
#         response = api_client.post('/logout/', HTTP_AUTHORIZATION='Token invalidtoken123')
#
#         # Assert that the response status code is 400 Bad Request
#         assert response.status_code == 400
#
#         # Assert that the response contains the expected error message
#         assert response.data['detail'] == "Invalid token or user already logged out."
#
#     def test_logout_deletes_token(self, api_client, user_with_token):
#         user, token = user_with_token
#         api_client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
#
#         response = api_client.post('/logout/')
#
#         assert response.status_code == 200
#         assert not Token.objects.filter(user=user).exists()
#
#     def test_logout_view_user_not_authenticated(api_client):
#         # Attempt to log out without providing a token
#         response = api_client.post('/api/logout/')
#
#         # Assert that the response status code is 401 Unauthorized
#         assert response.status_code == status.HTTP_401_UNAUTHORIZED
#         assert response.data['detail'] == "Authentication credentials were not provided."


# class ForgotPasswordRequestOTPViewTests(APITestCase):
#
#     def setUp(self):
#         self.user = CustomUser.objects.create_user(email='testuser@example.com', password='testpassword')
#         self.url = reverse('forgot-password')
#
#     def test_forgot_password_request_otp_success(self):
#         response = self.client.post(self.url, {'email': 'testuser@example.com'})
#         self.assertEqual(response.status_code, 200)
#         self.assertEqual(response.data, {'message': 'Password reset link sent to email'})
#
#     def test_forgot_password_request_otp_inactive_user(self):
#         # Create an inactive user
#         inactive_user = CustomUser.objects.create_user(email='inactiveuser@example.com', password='testpassword',
#                                                        is_active=False)
#
#         # Make a POST request to the forgot password endpoint with the inactive user's email
#         response = self.client.post(self.url, {'email': 'inactiveuser@example.com'})
#
#         # Check that the response indicates success, but no email should be sent
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertEqual(response.data, {'message': 'Password reset link sent to email'})
#
#         # Verify that no email was sent
#         self.assertEqual(len(mail.outbox), 0)
#
#     def test_forgot_password_request_otp_generates_unique_token(self):
#         # Create a user
#         user = CustomUser.objects.create_user(email='uniqueuser@example.com', password='testpassword')
#
#         # Make the first request to generate a token
#         response1 = self.client.post(self.url, {'email': user.email}, format='json')
#         self.assertEqual(response1.status_code, status.HTTP_200_OK)
#
#         # Extract token from the first response
#         uid1 = urlsafe_base64_encode(force_bytes(user.pk))
#         token1 = default_token_generator.make_token(user)
#
#         # Make a second request to generate a new token
#         response2 = self.client.post(self.url, {'email': user.email}, format='json')
#         self.assertEqual(response2.status_code, status.HTTP_200_OK)
#
#         # Extract token from the second response
#         uid2 = urlsafe_base64_encode(force_bytes(user.pk))
#         token2 = default_token_generator.make_token(user)
#
#         # Ensure both tokens are unique
#         self.assertNotEqual(token1, token2)
#
#     def test_forgot_password_request_otp_rate_limit_exceeded(self):
#         # Simulate exceeding the rate limit by making 6 requests
#         for _ in range(6):
#             response = self.client.post(self.url, {'email': self.user.email})
#
#         # The last request should be blocked due to rate limiting
#         self.assertEqual(response.status_code, 429)
#         self.assertIn('Request was throttled', response.data['detail'])
#
#     def test_forgot_password_request_otp_case_insensitive_email(self):
#         # Create a user with a specific email
#         CustomUser.objects.create_user(email='TestUser@example.com', password='testpassword')
#
#         # Prepare the request data with a different case for the email
#         data = {'email': 'testuser@example.com'}
#
#         # Send a POST request to the forgot password endpoint
#         response = self.client.post(self.url, data, format='json')
#
#         # Assert that the response status is 200 OK
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#
#         # Assert that the response contains the expected message
#         self.assertEqual(response.data['message'], 'Password reset link sent to email')
#
#         # Check that an email was sent
#         self.assertEqual(len(mail.outbox), 1)
#
#         # Assert that the email was sent to the correct address
#         self.assertEqual(mail.outbox[0].to, ['TestUser@example.com'])
#
#     def test_should_send_password_reset_link_to_valid_email(self):
#         response = self.client.post(self.url, {'email': 'Testuser@example.com'})
#         self.assertEqual(response.status_code, 200)
#         self.assertEqual(response.data['message'], 'Password reset link sent to email')
#         # Check that an email was sent
#         self.assertEqual(len(mail.outbox), 1)
#         self.assertIn('Password Reset Request', mail.outbox[0].subject)
#         self.assertIn('Testuser@example.com', mail.outbox[0].to)
#
#     def test_forgot_password_request_otp_empty_email(self):
#         response = self.client.post(self.url, {'email': ''})
#         self.assertEqual(response.status_code, 400)
#         self.assertEqual(response.data, {'error': 'Email not found'})
#
#     def test_forgot_password_request_otp_email_not_found(self):
#         response = self.client.post(self.url, {'email': 'nonexistent@example.com'})
#         self.assertEqual(response.status_code, 400)
#         self.assertEqual(response.data, {'error': 'Email not found'})
#
#     def test_forgot_password_request_otp_missing_email(self):
#         response = self.client.post(self.url, data={})
#         self.assertEqual(response.status_code, 400)
#         self.assertEqual(response.data, {'error': 'Email not found'})
#
#     def test_should_not_send_reset_email_if_email_is_invalid_format(self):
#         invalid_email = 'invalid-email-format'
#         response = self.client.post(self.url, {'email': invalid_email})
#         self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
#         self.assertEqual(response.data, {'error': 'Email not found'})


# class ResetPasswordViewTest(TestCase):
#     def setUp(self):
#         self.client = APIClient()
#         self.user = CustomUser.objects.create_user(email='testuser@example.com', password='old_password')
#         self.uid = urlsafe_base64_encode(force_bytes(self.user.pk))
#         self.token = default_token_generator.make_token(self.user)
#
#     def test_reset_password_invalid_user_empty_uid(self):
#         response = self.client.post('/api/reset-password/', {
#             'uid': '',
#             'token': self.token,
#             'new_password': 'new_password123',
#             'confirm_password': 'new_password123'
#         })
#         self.assertEqual(response.status_code, 404)
#         self.assertEqual(response.data['error'], 'Invalid user')
#
#     def test_reset_password_invalid_user_malformed_uid(self):
#         malformed_uid = 'invalid_uid'
#         response = self.client.post('/api/reset-password/', {
#             'uid': malformed_uid,
#             'token': self.token,
#             'new_password': 'new_password123',
#             'confirm_password': 'new_password123'
#         })
#         self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
#         self.assertEqual(response.data, {'error': 'Invalid user'})
#
#     def test_reset_password_invalid_user(self):
#         # Prepare the request data with an invalid UID
#         invalid_uid = urlsafe_base64_encode(force_bytes(9999)).decode()  # Assuming 9999 is a non-existent user ID
#         data = {
#             'uid': invalid_uid,
#             'token': self.token,
#             'new_password': 'new_password123',
#             'confirm_password': 'new_password123'
#         }
#
#         # Make the POST request to the reset password endpoint
#         response = self.client.post('/api/reset-password/', data, format='json')
#
#         # Assert that the response contains the 'Invalid user' error
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
#         self.assertEqual(response.data['error'], 'Invalid user')
#
#     def test_reset_password_view_invalid_token(self):
#         response = self.client.post('/api/reset-password/', {
#             'uid': self.uid,
#             'token': '',
#             'new_password': 'new_password123',
#             'confirm_password': 'new_password123'
#         })
#         self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
#         self.assertEqual(response.data['error'], 'Invalid or expired token')
#
#     def test_reset_password_invalid_token(self):
#         invalid_token = 'invalid-token'
#         response = self.client.post('/api/reset-password/', {
#             'uid': self.uid,
#             'token': invalid_token,
#             'new_password': 'new_password123',
#             'confirm_password': 'new_password123'
#         })
#         self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
#         self.assertEqual(response.data['error'], 'Invalid or expired token')
#
#     def test_reset_password_with_expired_token(self):
#         # Simulate an expired token
#         self.token = 'expired-token'  # Assuming this token is expired
#
#         response = self.client.post('/reset-password/', {
#             'uid': self.uid,
#             'token': self.token,
#             'new_password': 'new_password123',
#             'confirm_password': 'new_password123'
#         })
#
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
#         self.assertEqual(response.data['error'], 'Invalid or expired token')
#
#     def test_reset_password_success(self):
#         new_password = 'new_secure_password'
#         response = self.client.post('/api/reset-password/', {
#             'uid': self.uid,
#             'token': self.token,
#             'new_password': new_password,
#             'confirm_password': new_password
#         })
#         self.assertEqual(response.status_code, 200)
#         self.assertEqual(response.data['message'], 'Password reset successful')
#         self.user.refresh_from_db()
#         self.assertTrue(self.user.check_password(new_password))
#
#     def test_reset_password_passwords_do_not_match(self):
#         response = self.client.post('/api/reset-password/', data={
#             'uid': self.uid,
#             'token': self.token,
#             'new_password': 'new_password123',
#             'confirm_password': 'different_password123'
#         })
#         self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
#         self.assertEqual(response.data['error'], 'Passwords do not match')
#
#     def test_reset_password_with_empty_request_body(self):
#         response = self.client.post('/api/reset-password/', data={}, format='json')
#         self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
#         self.assertIn('error', response.data)
#         self.assertEqual(response.data['error'], 'Passwords do not match')
#
#     def test_reset_password_rate_limiting(self):
#         # Simulate 6 requests from the same IP
#         for _ in range(5):
#             response = self.client.post('/api/reset-password/', {
#                 'uid': self.uid,
#                 'token': self.token,
#                 'new_password': 'new_password123',
#                 'confirm_password': 'new_password123'
#             })
#             self.assertNotEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
#
#         # The 6th request should be rate limited
#         response = self.client.post('/api/reset-password/', {
#             'uid': self.uid,
#             'token': self.token,
#             'new_password': 'new_password123',
#             'confirm_password': 'new_password123'
#         })
#         self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)



# class UpdateKYCViewTest(TestCase):
#     def setUp(self):
#         self.client = APIClient()
#         self.user = CustomUser.objects.create_user(email='testuser@example.com', password='password123')
#         self.token = Token.objects.create(user=self.user)
#         self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)
#         self.kyc_data = {
#             'bvn': '12345678901',
#             'nin': '98765432101',
#             'driver_license': None,  # Assuming no file upload for testing
#         }
#
#     def test_should_return_validation_errors_when_invalid_kyc_data_is_submitted(self):
#         invalid_kyc_data = {
#             'bvn': '',  # Assuming bvn is required
#             'nin': '',  # Assuming nin is required
#         }
#         response = self.client.post(reverse('update-kyc'), data=invalid_kyc_data, format='json')
#         self.assertEqual(response.status_code, 400)
#         self.assertIn('bvn', response.data)
#         self.assertIn('nin', response.data)
#
#     def test_update_kyc_serializer_failure(self):
#         invalid_kyc_data = {
#             'bvn': '',  # Assuming bvn is required and cannot be empty
#             'nin': '98765432101',
#         }
#         response = self.client.post(reverse('update-kyc'), data=invalid_kyc_data, format='json')
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
#         self.assertIn('bvn', response.data)
#         self.assertEqual(response.data['bvn'], ['This field may not be blank.'])
#
#     def test_update_kyc_missing_fields(self):
#         incomplete_kyc_data = {
#             'bvn': '',  # Assuming bvn is required
#             'nin': '',  # Assuming nin is required
#             # 'driver_license' is optional
#         }
#         response = self.client.post(reverse('update-kyc'), incomplete_kyc_data, format='json')
#         self.assertEqual(response.status_code, 400)
#         self.assertIn('This field may not be blank.', response.data['bvn'])
#         self.assertIn('This field may not be blank.', response.data['nin'])
#
#     def test_concurrent_kyc_updates(self):
#         client2 = APIClient()
#         client2.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)
#
#         response1 = self.client.post(reverse('update-kyc'), {
#             'bvn': '12345678901',
#             'nin': '98765432101',
#         }, format='json')
#         self.assertEqual(response1.status_code, status.HTTP_200_OK)
#
#         response2 = client2.post(reverse('update-kyc'), {
#             'bvn': '12345678902',
#             'nin': '98765432102',
#         }, format='json')
#         self.assertEqual(response2.status_code, status.HTTP_200_OK)
#
#         kyc_record = KYC.objects.get(user=self.user)
#         self.assertIn(kyc_record.bvn, ['12345678901', '12345678902'])
#         self.assertIn(kyc_record.nin, ['98765432101', '98765432102'])
#
#     def test_partial_update_kyc_information(self):
#         initial_kyc_data = {
#             'bvn': '12345678901',
#             'nin': '98765432101',
#         }
#         KYC.objects.create(user=self.user, **initial_kyc_data)
#
#         partial_kyc_data = {
#             'bvn': '12345678902',  # Update only the BVN
#         }
#         response = self.client.post(reverse('update-kyc'), data=partial_kyc_data)
#         updated_kyc = KYC.objects.get(user=self.user)
#
#         self.assertEqual(response.status_code, 200)
#         self.assertEqual(updated_kyc.bvn, '12345678902')  # Ensure BVN is updated
#         self.assertEqual(updated_kyc.nin, '98765432101')  # Ensure NIN remains unchanged
#         self.assertEqual(response.data['message'], 'KYC updated successfully')
#
#     def test_update_kyc_view_no_permission(self):
#         another_user = CustomUser.objects.create_user(email='anotheruser@example.com', password='password123')
#         another_token = Token.objects.create(user=another_user)
#         self.client.credentials(HTTP_AUTHORIZATION='Token ' + another_token.key)
#
#         response = self.client.post(reverse('update-kyc'), self.kyc_data)
#         self.assertEqual(response.status_code, 403)
#
#     def test_create_new_kyc_record_if_none_exists(self):
#         KYC.objects.filter(user=self.user).delete()
#         self.assertFalse(KYC.objects.filter(user=self.user).exists())
#
#         response = self.client.post(reverse('update-kyc'), self.kyc_data)
#         self.assertEqual(response.status_code, 200)
#         self.assertTrue(KYC.objects.filter(user=self.user).exists())
#
#         kyc_record = KYC.objects.get(user=self.user)
#         self.assertEqual(kyc_record.bvn, self.kyc_data['bvn'])
#         self.assertEqual(kyc_record.nin, self.kyc_data['nin'])
#
#     def test_update_kyc_unauthorized(self):
#         self.client.credentials()  # Clear credentials to simulate unauthorized access
#         response = self.client.post(reverse('update-kyc'), self.kyc_data)
#         self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
#
#     def test_update_kyc_success(self):
#         valid_kyc_data = {
#             'bvn': '12345678901',
#             'nin': '98765432101',
#         }
#         url = reverse('update-kyc')
#         response = self.client.post(url, data=valid_kyc_data, format='json')
#
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertEqual(response.data['message'], 'KYC updated successfully')
#         kyc_record = KYC.objects.get(user=self.user)
#         self.assertEqual(kyc_record.bvn, valid_kyc_data['bvn'])
#         self.assertEqual(kyc_record.nin, valid_kyc_data['nin'])


# @pytest.mark.django_db
# class TestUpdateVehicleInfoView:
#     def setup_method(self):
#         self.client = APIClient()
#         self.user = CustomUser.objects.create_user(email='testuser@example.com', password='testpassword')
#         self.token = Token.objects.create(user=self.user)
#         self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)
#         self.url = reverse('update-vehicle-info')
#
#     def test_update_vehicle_info_view_handles_large_payload_gracefully(self):
#         # Generate a large payload for vehicle data
#         large_payload = {
#             'make': 'Toyota' * 1000,
#             'model': 'Corolla' * 1000,
#             'year': 2022,
#             'color': 'Blue' * 1000,
#             'license_plate': 'XYZ1234' * 1000
#         }
#
#         # Send a POST request with the large payload
#         response = self.client.post(self.url, data=large_payload, format='json')
#
#         # Assert that the response status code is 200 OK
#         assert response.status_code == 200
#
#         # Assert that the response contains a success message
#         assert response.data['message'] == 'Vehicle information updated successfully'
#
#         # Optionally, assert that the vehicle data in the response matches the large payload
#         vehicle_data = response.data['vehicle']
#         assert vehicle_data['make'] == 'Toyota' * 1000
#         assert vehicle_data['model'] == 'Corolla' * 1000
#         assert vehicle_data['year'] == 2022
#         assert vehicle_data['color'] == 'Blue' * 1000
#         assert vehicle_data['license_plate'] == 'XYZ1234' * 1000
#
#     def test_should_not_create_duplicate_vehicle_record(self):
#         # Create an initial vehicle record for the user
#         Vehicle.objects.create(user=self.user, make='Toyota', model='Corolla')
#
#         # Prepare the data for updating vehicle information
#         data = {'make': 'Honda', 'model': 'Civic'}
#
#         # Send a POST request to update the vehicle information
#         response = self.client.post(self.url, data, format='json')
#
#         # Check that the response status is 200 OK
#         assert response.status_code == 200
#
#         # Verify that only one vehicle record exists for the user
#         assert Vehicle.objects.filter(user=self.user).count() == 1
#
#         # Verify that the vehicle record has been updated with the new data
#         vehicle = Vehicle.objects.get(user=self.user)
#         assert vehicle.make == 'Honda'
#         assert vehicle.model == 'Civic'
#
#     def test_partial_update_vehicle_info(self):
#         # Prepare initial vehicle data
#         initial_data = {
#             'make': 'Toyota',
#             'model': 'Camry',
#             'year': 2020
#         }
#         # Create a vehicle for the user
#         Vehicle.objects.create(user=self.user, **initial_data)
#
#         # Prepare partial update data
#         update_data = {
#             'model': 'Corolla'
#         }
#
#         # Send POST request to update vehicle info
#         response = self.client.post(self.url, update_data, format='json')
#
#         # Fetch the updated vehicle from the database
#         updated_vehicle = Vehicle.objects.get(user=self.user)
#
#         # Assert the response status code
#         assert response.status_code == 200
#
#         # Assert the response message
#         assert response.data['message'] == 'Vehicle information updated successfully'
#
#         # Assert the vehicle fields were updated correctly
#         assert updated_vehicle.make == 'Toyota'  # Unchanged
#         assert updated_vehicle.model == 'Corolla'  # Updated
#         assert updated_vehicle.year == 2020  # Unchanged
#
#     def test_update_vehicle_info_unauthenticated(self):
#         url = reverse('update-vehicle-info')
#         response = self.client.post(url, data={'make': 'Toyota', 'model': 'Camry'})
#         assert response.status_code == 401
#
#     def test_create_new_vehicle_record_when_none_exists(self):
#         # Simulate a user without an existing vehicle record
#         new_user = CustomUser.objects.create_user(email='newuser@example.com', password='newpassword')
#         new_token = Token.objects.create(user=new_user)
#         self.client.credentials(HTTP_AUTHORIZATION='Token ' + new_token.key)
#
#         # Define the vehicle data to be sent in the request
#         vehicle_data = {
#             'make': 'Toyota',
#             'model': 'Corolla',
#             'year': 2021,
#             'license_plate': 'XYZ1234'
#         }
#
#         # Send a POST request to update vehicle information
#         response = self.client.post(self.url, vehicle_data, format='json')
#
#         # Assert that the response status code is 200 OK
#         assert response.status_code == 200
#
#         # Assert that the response data contains the expected message
#         assert response.data['message'] == 'Vehicle information updated successfully'
#
#         # Assert that a vehicle record has been created for the new user
#         vehicle_exists = Vehicle.objects.filter(user=new_user).exists()
#         assert vehicle_exists
#
#     def test_update_vehicle_info_with_invalid_data(self):
#         invalid_data = {
#             'license_plate': '',  # Assuming license_plate is a required field
#             'model': 'Tesla',  # Valid field
#             # Add more invalid fields or missing required fields as needed
#         }
#         response = self.client.post(self.url, invalid_data, format='json')
#         assert response.status_code == 400
#         assert 'license_plate' in response.data  # Check if the error for license_plate is present
#
#     def test_update_vehicle_info_missing_fields(self):
#         # Simulate a request with missing required vehicle fields
#         response = self.client.post(self.url, data={})
#
#         # Assert that the response status code is 400 Bad Request
#         assert response.status_code == 400
#
#         # Assert that the response contains error messages for missing fields
#         assert 'error' in response.data
#
#     def test_update_vehicle_info_successfully(self):
#         # Prepare test data
#         vehicle_data = {
#             'make': 'Toyota',
#             'model': 'Corolla',
#             'year': 2020,
#             'license_plate': 'XYZ1234'
#         }
#
#         # Send POST request to update vehicle information
#         response = self.client.post(self.url, vehicle_data, format='json')
#
#         # Assert the response status code and message
#         assert response.status_code == 200
#         assert response.data['message'] == 'Vehicle information updated successfully'
#
#         # Assert the vehicle data in the response
#         vehicle = response.data['vehicle']
#         assert vehicle['make'] == 'Toyota'
#         assert vehicle['model'] == 'Corolla'
#         assert vehicle['year'] == 2020
#         assert vehicle['license_plate'] == 'XYZ1234'
#
#     def test_update_vehicle_info_success(client, django_user_model):
#         # Create a test user and authenticate
#         user = django_user_model.objects.create_user(email='testuser@example.com', password='testpassword')
#         token = Token.objects.create(user=user)
#         client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
#
#         # Create initial vehicle data
#         vehicle = Vehicle.objects.create(user=user, make='Toyota', model='Camry', year=2015)
#
#         # Define the URL for updating vehicle info
#         url = reverse('update-vehicle-info')
#
#         # Define new vehicle data to update
#         update_data = {
#             'make': 'Honda',
#             'model': 'Accord',
#             'year': 2020
#         }
#
#         # Make the POST request to update vehicle info
#         response = client.post(url, update_data, format='json')
#
#         # Assert the response status code
#         assert response.status_code == 200
#
#         # Assert the response data
#         assert response.data['message'] == 'Vehicle information updated successfully'
#         assert response.data['vehicle']['make'] == 'Honda'
#         assert response.data['vehicle']['model'] == 'Accord'
#         assert response.data['vehicle']['year'] == 2020
#
#     def test_concurrent_vehicle_updates(self):
#         user = CustomUser.objects.create_user(email='concurrentuser@example.com', password='testpassword')
#         token = Token.objects.create(user=user)
#         self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
#         url = reverse('update-vehicle-info')
#
#         # Initial vehicle data
#         initial_data = {'make': 'Toyota', 'model': 'Corolla', 'year': 2020}
#         response = self.client.post(url, initial_data)
#         assert response.status_code == 200
#
#         # Concurrent update data
#         update_data_1 = {'make': 'Honda', 'model': 'Civic', 'year': 2021}
#         update_data_2 = {'make': 'Ford', 'model': 'Focus', 'year': 2022}
#
#         # Simulate concurrent requests
#         response_1 = self.client.post(url, update_data_1)
#         response_2 = self.client.post(url, update_data_2)
#
#         # Ensure both requests are successful
#         assert response_1.status_code == 200
#         assert response_2.status_code == 200
#
#         # Fetch the updated vehicle data
#         vehicle = Vehicle.objects.get(user=user)
#
#         # Check that the vehicle data is consistent and one of the updates was applied
#         assert vehicle.make in ['Honda', 'Ford']
#         assert vehicle.model in ['Civic', 'Focus']
#         assert vehicle.year in [2021, 2022]


# @pytest.mark.django_db
# class TestUpdatePersonalInfoView:
#     def setup_method(self):
#         self.client = APIClient()
#         self.user = CustomUser.objects.create_user(username='testuser', password='testpass')
#         self.social_media = SocialMediaLink.objects.create(user=self.user)
#         self.url = reverse('update_personal_info')
#
#     def test_should_maintain_existing_social_media_links_if_no_new_data_provided(self):
#         self.client.login(username='testuser', password='testpass')
#         initial_data = {
#             'facebook': 'https://facebook.com/testuser',
#             'twitter': 'https://twitter.com/testuser'
#         }
#         self.social_media.facebook = initial_data['facebook']
#         self.social_media.twitter = initial_data['twitter']
#         self.social_media.save()
#
#         response = self.client.post(self.url, {}, format='json')
#
#         assert response.status_code == 200
#         assert response.data['social_media']['facebook'] == initial_data['facebook']
#         assert response.data['social_media']['twitter'] == initial_data['twitter']
#
#     def test_update_personal_info_creates_social_media_links_if_missing(self):
#         self.client.login(username='testuser', password='testpass')
#         data = {
#             'first_name': 'John',
#             'last_name': 'Doe',
#             # Assuming social media fields are part of the request data
#             'twitter': 'johndoe_twitter',
#             'facebook': 'johndoe_facebook'
#         }
#         response = self.client.post(self.url, data, format='json')
#
#         assert response.status_code == 200
#         assert response.data['user']['first_name'] == 'John'
#         assert response.data['user']['last_name'] == 'Doe'
#         assert response.data['social_media']['twitter'] == 'johndoe_twitter'
#         assert response.data['social_media']['facebook'] == 'johndoe_facebook'
#
#     def test_should_return_validation_errors_when_social_media_data_is_invalid(self):
#         self.client.login(username='testuser', password='testpass')
#         invalid_social_media_data = {
#             'facebook': 'not_a_valid_url',
#             'twitter': 'another_invalid_url'
#         }
#         response = self.client.post(self.url, invalid_social_media_data, format='json')
#         assert response.status_code == 400
#         assert 'social_media_errors' in response.data
#         assert 'facebook' in response.data['social_media_errors']
#         assert 'twitter' in response.data['social_media_errors']
#
#     def test_update_personal_info_successfully_updates_user_and_social_media_links(self):
#         self.client.login(username='testuser', password='testpass')
#         data = {
#             'first_name': 'UpdatedName',
#             'last_name': 'UpdatedLastName',
#             'social_media_link': 'https://updatedlink.com'
#         }
#         response = self.client.post(self.url, data, format='json')
#
#         assert response.status_code == 200
#         assert response.data['user']['first_name'] == 'UpdatedName'
#         assert response.data['user']['last_name'] == 'UpdatedLastName'
#         assert response.data['social_media']['social_media_link'] == 'https://updatedlink.com'
#
#     def test_should_not_update_email_even_if_provided(self):
#         self.client.force_authenticate(user=self.user)
#         update_data = {
#             'email': 'newemail@example.com',
#             'first_name': 'NewFirstName',
#             'last_name': 'NewLastName'
#         }
#         response = self.client.post(self.url, update_data, format='json')
#
#         self.user.refresh_from_db()
#         assert response.status_code == 200
#         assert self.user.email == 'testuser@example.com'  # Assuming initial email is 'testuser@example.com'
#         assert self.user.first_name == 'NewFirstName'
#         assert self.user.last_name == 'NewLastName'
#
#     @pytest.mark.django_db
#     def test_update_personal_info_view_returns_200_with_updated_data(api_client, user_factory,
#                                                                      social_media_link_factory):
#         user = user_factory()
#         social_media = social_media_link_factory(user=user)
#         api_client.force_authenticate(user=user)
#
#         url = reverse('update_personal_info')
#         data = {
#             'first_name': 'UpdatedFirstName',
#             'last_name': 'UpdatedLastName',
#             'twitter': 'https://twitter.com/updated',
#             'facebook': 'https://facebook.com/updated'
#         }
#
#         response = api_client.post(url, data, format='json')
#
#         assert response.status_code == 200
#         assert response.data['user']['first_name'] == 'UpdatedFirstName'
#         assert response.data['user']['last_name'] == 'UpdatedLastName'
#         assert response.data['social_media']['twitter'] == 'https://twitter.com/updated'
#         assert response.data['social_media']['facebook'] == 'https://facebook.com/updated'
#
#     def test_update_personal_info_view_unauthenticated(self):
#         url = reverse('update_personal_info')
#         response = self.client.post(url, {})
#         assert response.status_code == 401
#         assert response.data['detail'] == 'Authentication credentials were not provided.'
#
#     @pytest.mark.django_db
#     def test_update_personal_info_view_invalid_user_data(self):
#         self.client.login(username='testuser', password='testpass')
#         invalid_data = {
#             'username': '',  # Assuming username cannot be empty
#             'social_media_link': 'invalid_url'  # Assuming this field requires a valid URL
#         }
#         response = self.client.post(self.url, data=invalid_data, format='json')
#         assert response.status_code == 400
#         assert 'user_errors' in response.data
#         assert 'social_media_errors' in response.data
#         assert 'username' in response.data['user_errors']
#         assert 'social_media_link' in response.data['social_media_errors']
#
#     def test_should_return_400_if_user_and_social_media_data_invalid(api_client, user_factory):
#         user = user_factory()
#         api_client.force_authenticate(user=user)
#
#         url = reverse('update_personal_info')
#         invalid_data = {
#             'first_name': '',  # Assuming first name cannot be empty
#             'twitter': 'not_a_valid_url'  # Assuming URL should be valid
#         }
#
#         response = api_client.post(url, invalid_data, format='json')
#
#         assert response.status_code == 400
#         assert 'user_errors' in response.data
#         assert 'social_media_errors' in response.data


# @pytest.mark.django_db
# class TestUpdateSubscriptionPlanView:
#     def setup_method(self):
#         self.client = APIClient()
#         self.user = CustomUser.objects.create_user(username='testuser', password='testpass')
#         self.client.force_authenticate(user=self.user)
#         self.url = reverse('update-subscription-plan')
#
#     def test_update_subscription_plan_unauthenticated(self):
#         response = APIClient().put(self.url, {'plan_name': 'premium'})
#         assert response.status_code == 401
#
#     def test_update_subscription_plan_case_insensitive(self):
#         # Create a subscription plan with uppercase name
#         SubscriptionPlan.objects.create(name='PREMIUM', duration=30)
#
#         # Test with lowercase plan name
#         response = self.client.put(self.url, {'plan_name': 'premium'}, format='json')
#
#         assert response.status_code == 200
#         assert response.data['message'] == "Subscription plan updated successfully."
#
#         # Verify that the subscription plan was updated correctly
#         subscription = Subscription.objects.get(user=self.user)
#         assert subscription.plan.name == 'PREMIUM'
#
#     def test_update_subscription_plan_calculates_correct_end_date(self, mocker):
#         # Mock the get_user_from_token function to return the test user
#         mocker.patch('path.to.get_user_from_token', return_value=self.user)
#
#         # Create a subscription plan with a specific duration
#         plan_duration = 30
#         plan = SubscriptionPlan.objects.create(name='premium', duration=plan_duration)
#
#         # Mock the request data
#         request_data = {'plan_name': 'premium'}
#
#         # Perform the PUT request
#         response = self.client.put(self.url, data=request_data, format='json')
#
#         # Refresh the subscription object from the database
#         subscription = Subscription.objects.get(user=self.user)
#
#         # Calculate the expected end date
#         expected_end_date = subscription.start_date + timedelta(days=plan_duration)
#
#         # Assert that the response is successful
#         assert response.status_code == 200
#         # Assert that the end date is calculated correctly
#         assert subscription.end_date == expected_end_date
#
#     def test_create_new_subscription_record_if_none_exists(self):
#         # Create a new user and authenticate
#         user = CustomUser.objects.create_user(username='newuser', password='newpass')
#         self.client.force_authenticate(user=user)
#
#         # Create a subscription plan
#         plan_name = 'premium'
#         SubscriptionPlan.objects.create(name=plan_name, duration=30)
#
#         # Send PUT request to update subscription plan
#         response = self.client.put(self.url, {'plan_name': plan_name})
#
#         # Check if the subscription was created
#         assert response.status_code == 200
#         assert response.data['message'] == "Subscription plan updated successfully."
#         assert Subscription.objects.filter(user=user).exists()
#
#     def test_update_existing_subscription_plan(self, mocker):
#         # Mock the get_user_from_token function to return the test user
#         mocker.patch('path.to.get_user_from_token', return_value=self.user)
#
#         # Create a subscription plan and a subscription for the user
#         plan = SubscriptionPlan.objects.create(name='basic', duration=30)
#         subscription = Subscription.objects.create(user=self.user, plan=plan, start_date=timezone.now(),
#                                                    end_date=timezone.now() + timedelta(days=30))
#
#         # Prepare the data for the PUT request
#         new_plan = SubscriptionPlan.objects.create(name='premium', duration=60)
#         data = {'plan_name': 'premium'}
#
#         # Perform the PUT request
#         response = self.client.put(self.url, data, format='json')
#
#         # Refresh the subscription from the database
#         subscription.refresh_from_db()
#
#         # Assert the response status code
#         assert response.status_code == 200
#
#         # Assert the subscription plan has been updated
#         assert subscription.plan == new_plan
#
#         # Assert the subscription dates have been updated
#         assert subscription.start_date is not None
#         assert subscription.end_date == subscription.start_date + timedelta(days=new_plan.duration)
#
#     def test_update_subscription_plan_successfully(self):
#         # Create a subscription plan
#         plan = SubscriptionPlan.objects.create(name='premium', duration=30)
#
#         # Prepare the data with a valid plan name
#         data = {'plan_name': 'premium'}
#
#         # Perform the PUT request
#         response = self.client.put(self.url, data, format='json')
#
#         # Assert the response status code
#         assert response.status_code == 200
#
#         # Assert the response message
#         assert response.data['message'] == "Subscription plan updated successfully."
#
#         # Fetch the updated subscription
#         subscription = Subscription.objects.get(user=self.user)
#
#         # Assert the subscription plan is updated
#         assert subscription.plan == plan
#
#     def test_update_subscription_plan_no_plan_name(self):
#         response = self.client.put(self.url, {})
#         assert response.status_code == 400
#         assert response.data == {"error": "Plan name is required."}
#
#     def test_update_subscription_plan_missing_plan_name(self):
#         response = self.client.put(self.url, data={})
#         assert response.status_code == 400
#         assert response.data == {"error": "Plan name is required."}
#
#     def test_update_subscription_plan_not_found(self):
#         # Arrange
#         invalid_plan_name = 'nonexistent_plan'
#         data = {'plan_name': invalid_plan_name}
#
#         # Act
#         response = self.client.put(self.url, data, format='json')
#
#         # Assert
#         assert response.status_code == 404
#         assert response.data['error'] == 'Subscription plan not found.'
#
#     def test_update_subscription_plan_invalid_plan_name(self):
#         # Arrange
#         invalid_plan_name = "nonexistent_plan"
#         data = {'plan_name': invalid_plan_name}
#
#         # Act
#         response = self.client.put(self.url, data, format='json')
#
#         # Assert
#         assert response.status_code == 404
#         assert response.data['error'] == "Subscription plan not found."
