from django.test import TestCase
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model

from Auth.models import CustomUser, OTP
from Profile.models import KYC, Vehicle, SubscriptionPlan, Subscription

User = get_user_model()


class CustomUserModelTestCase(TestCase):
    """Test cases for CustomUser model."""
    
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
    
    def test_user_creation(self):
        """Test user is created with correct fields."""
        self.assertEqual(self.user.email, 'test@example.com')
        self.assertTrue(self.user.check_password('testpass123'))
        self.assertFalse(self.user.is_email_verified)
    
    def test_user_str(self):
        """Test user string representation."""
        self.assertEqual(str(self.user), 'test@example.com')
    
    def test_user_is_not_staff_by_default(self):
        """Test user is not staff by default."""
        self.assertFalse(self.user.is_staff)
    
    def test_user_manager(self):
        """Test UserManager create_user method."""
        user = CustomUser.objects.create_user(
            email='new@example.com',
            password='password123'
        )
        self.assertEqual(user.email, 'new@example.com')
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)


class OTPModelTestCase(TestCase):
    """Test cases for OTP model."""
    
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.otp = OTP.objects.create(user=self.user)
    
    def test_otp_creation(self):
        """Test OTP is created with code."""
        self.assertIsNotNone(self.otp.code)
        self.assertEqual(len(self.otp.code), 4)
        self.assertFalse(self.otp.is_used)
    
    def test_otp_expiration(self):
        """Test OTP expiration logic."""
        self.assertFalse(self.otp.is_expired())
    
    def test_otp_str(self):
        """Test OTP string representation."""
        self.assertIn(self.user.email, str(self.otp))


class RegisterViewTestCase(APITestCase):
    """Test cases for RegisterView."""
    
    def setUp(self):
        self.client = APIClient()
        self.url = '/auth/v1/register/'
        self.free_plan = SubscriptionPlan.objects.create(name='free', price=0)
    
    def test_successful_registration(self):
        """Test successful user registration."""
        data = {
            'email': 'newuser@example.com',
            'password': 'securepassword123',
            'first_name': 'New',
            'last_name': 'User'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'newuser@example.com')
        self.assertFalse(response.data['is_email_verified'])
    
    def test_registration_creates_kyc_vehicle_subscription(self):
        """Test registration creates KYC, Vehicle, and Subscription."""
        data = {
            'email': 'complete@example.com',
            'password': 'password123'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        user = CustomUser.objects.get(email='complete@example.com')
        self.assertTrue(hasattr(user, 'kyc'))
        self.assertTrue(hasattr(user, 'vehicle'))
        self.assertTrue(hasattr(user, 'subscriptions'))
    
    def test_registration_creates_otp(self):
        """Test registration creates OTP for email verification."""
        data = {
            'email': 'otp@example.com',
            'password': 'password123'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(OTP.objects.filter(user__email='otp@example.com').exists())
    
    def test_registration_duplicate_email(self):
        """Test registration with duplicate email fails."""
        CustomUser.objects.create_user(email='duplicate@example.com', password='password123')
        data = {
            'email': 'duplicate@example.com',
            'password': 'password123'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def test_registration_invalid_email(self):
        """Test registration with invalid email fails."""
        data = {
            'email': 'not-an-email',
            'password': 'password123'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class LoginViewTestCase(APITestCase):
    """Test cases for LoginView."""
    
    def setUp(self):
        self.client = APIClient()
        self.url = '/auth/v1/login/'
        self.user = CustomUser.objects.create_user(
            email='login@example.com',
            password='password123'
        )
        self.user.is_email_verified = True
        self.user.save()
    
    def test_successful_login(self):
        """Test successful login returns token and user data."""
        data = {
            'email': 'login@example.com',
            'password': 'password123'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials fails."""
        data = {
            'email': 'login@example.com',
            'password': 'wrongpassword'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
    
    def test_login_unverified_email(self):
        """Test login with unverified email fails."""
        user = CustomUser.objects.create_user(
            email='unverified@example.com',
            password='password123'
        )
        data = {
            'email': 'unverified@example.com',
            'password': 'password123'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_login_nonexistent_user(self):
        """Test login with nonexistent user fails."""
        data = {
            'email': 'nonexistent@example.com',
            'password': 'password123'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class LogoutViewTestCase(APITestCase):
    """Test cases for LogoutView."""
    
    def setUp(self):
        self.client = APIClient()
        self.url = '/auth/v1/logout/'
        self.user = CustomUser.objects.create_user(
            email='logout@example.com',
            password='password123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
    
    def test_successful_logout(self):
        """Test successful logout deletes token."""
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(Token.objects.filter(user=self.user).exists())
    
    def test_logout_unauthenticated(self):
        """Test logout without authentication."""
        self.client.credentials()
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class VerifyOTPViewTestCase(APITestCase):
    """Test cases for VerifyOTPView."""
    
    def setUp(self):
        self.client = APIClient()
        self.url = '/auth/v1/verify-otp/'
        self.user = CustomUser.objects.create_user(
            email='verify@example.com',
            password='password123'
        )
        self.otp = OTP.objects.create(user=self.user)
    
    def test_successful_verification(self):
        """Test successful OTP verification."""
        data = {
            'email': 'verify@example.com',
            'code': self.otp.code
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_email_verified)
    
    def test_invalid_otp(self):
        """Test verification with invalid OTP fails."""
        data = {
            'email': 'verify@example.com',
            'code': '0000'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_expired_otp(self):
        """Test verification with expired OTP fails."""
        self.otp.expires_at = timezone.now() - timedelta(hours=1)
        self.otp.save()
        
        data = {
            'email': 'verify@example.com',
            'code': self.otp.code
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_already_used_otp(self):
        """Test verification with already used OTP fails."""
        self.otp.is_used = True
        self.otp.save()
        
        data = {
            'email': 'verify@example.com',
            'code': self.otp.code
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class ResendOTPViewTestCase(APITestCase):
    """Test cases for ResendOTPView."""
    
    def setUp(self):
        self.client = APIClient()
        self.url = '/auth/v1/resend-otp/'
        self.user = CustomUser.objects.create_user(
            email='resend@example.com',
            password='password123'
        )
    
    def test_successful_resend(self):
        """Test successful OTP resend."""
        data = {'email': 'resend@example.com'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(OTP.objects.filter(user=self.user, is_used=False).count() > 1)
    
    def test_resend_nonexistent_user(self):
        """Test resend OTP for nonexistent user fails."""
        data = {'email': 'nonexistent@example.com'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class ForgotPasswordViewTestCase(APITestCase):
    """Test cases for ForgotPasswordRequestOTPView."""
    
    def setUp(self):
        self.client = APIClient()
        self.url = '/auth/v1/forgot-password/'
        self.user = CustomUser.objects.create_user(
            email='forgot@example.com',
            password='password123'
        )
    
    def test_successful_request(self):
        """Test successful forgot password request."""
        data = {'email': 'forgot@example.com'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_nonexistent_user(self):
        """Test forgot password for nonexistent user."""
        data = {'email': 'nonexistent@example.com'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class ResetPasswordViewTestCase(APITestCase):
    """Test cases for ResetPasswordView."""
    
    def setUp(self):
        self.client = APIClient()
        self.url = '/auth/v1/reset-password/'
        self.user = CustomUser.objects.create_user(
            email='reset@example.com',
            password='oldpassword123'
        )
        self.otp = OTP.objects.create(user=self.user)
    
    def test_successful_reset(self):
        """Test successful password reset."""
        data = {
            'email': 'reset@example.com',
            'code': self.otp.code,
            'new_password': 'newpassword123'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword123'))
    
    def test_reset_invalid_otp(self):
        """Test reset with invalid OTP fails."""
        data = {
            'email': 'reset@example.com',
            'code': '0000',
            'new_password': 'newpassword123'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class GetUserFromTokenTestCase(TestCase):
    """Test cases for get_user_from_token function."""
    
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='token@example.com',
            password='password123'
        )
        self.token = Token.objects.create(user=self.user)
    
    def test_valid_token(self):
        """Test get_user_from_token with valid token."""
        from Auth.views import get_user_from_token
        from django.test import RequestFactory
        
        factory = RequestFactory()
        request = factory.get('/', HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        user = get_user_from_token(request)
        self.assertEqual(user, self.user)
    
    def test_invalid_token(self):
        """Test get_user_from_token with invalid token."""
        from Auth.views import get_user_from_token
        from django.test import RequestFactory
        from rest_framework.exceptions import AuthenticationFailed
        
        factory = RequestFactory()
        request = factory.get('/', HTTP_AUTHORIZATION='Token invalidtoken')
        
        with self.assertRaises(AuthenticationFailed):
            get_user_from_token(request)
    
    def test_missing_token(self):
        """Test get_user_from_token with missing token."""
        from Auth.views import get_user_from_token
        from django.test import RequestFactory
        from rest_framework.exceptions import AuthenticationFailed
        
        factory = RequestFactory()
        request = factory.get('/')
        
        with self.assertRaises(AuthenticationFailed):
            get_user_from_token(request)


class CustomUserViewSetTestCase(APITestCase):
    """Test cases for CustomUser ViewSet."""
    
    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(
            email='viewset@example.com',
            password='password123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
    
    def test_list_users(self):
        """Test listing users."""
        response = self.client.get('/auth/v1/api/users/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_retrieve_user(self):
        """Test retrieving single user."""
        response = self.client.get(f'/auth/v1/api/users/{self.user.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'viewset@example.com')


from django.utils import timezone
from datetime import timedelta