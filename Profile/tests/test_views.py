from django.test import TestCase
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework.authtoken.models import Token

from Auth.models import CustomUser
from Profile.models import KYC, Vehicle, SubscriptionPlan, Subscription, Notification, SocialMediaLink


class KYCModelTestCase(TestCase):
    """Test cases for KYC model."""
    
    def setUp(self):
        self.user = CustomUser.objects.create_user(email='test@example.com', password='testpass123')
        self.kyc = KYC.objects.create(user=self.user, bvn='12345678901', nin='12345678901')
    
    def test_kyc_creation(self):
        """Test KYC is created with correct fields."""
        self.assertEqual(self.kyc.bvn, '12345678901')
        self.assertEqual(self.kyc.nin, '12345678901')
        self.assertFalse(self.kyc.verified)
    
    def test_kyc_str(self):
        """Test KYC string representation."""
        self.assertIn('test@example.com', str(self.kyc))


class VehicleModelTestCase(TestCase):
    """Test cases for Vehicle model."""
    
    def setUp(self):
        self.user = CustomUser.objects.create_user(email='test@example.com', password='testpass123')
        self.vehicle = Vehicle.objects.create(
            user=self.user,
            vehicle_plate_number='ABC123',
            vehicle_type='Car',
            vehicle_brand='Toyota'
        )
    
    def test_vehicle_creation(self):
        """Test vehicle is created with correct fields."""
        self.assertEqual(self.vehicle.vehicle_plate_number, 'ABC123')
        self.assertEqual(self.vehicle.vehicle_type, 'Car')


class SubscriptionPlanModelTestCase(TestCase):
    """Test cases for SubscriptionPlan model."""
    
    def setUp(self):
        self.plan = SubscriptionPlan.objects.create(name='basic', price=1200, duration=30)
    
    def test_plan_creation(self):
        """Test subscription plan is created."""
        self.assertEqual(self.plan.name, 'basic')
        self.assertEqual(self.plan.price, 1200)


class UpdateKYCViewTestCase(APITestCase):
    """Test cases for UpdateKYCView."""
    
    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(email='kyc@example.com', password='password123')
        self.user.is_email_verified = True
        self.user.save()
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
    
    def test_update_kyc_success(self):
        """Test successful KYC update."""
        data = {'bvn': '12345678901', 'nin': '12345678901'}
        response = self.client.post('/profile/v1/update-kyc/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_update_kyc_missing_bvn(self):
        """Test KYC update with missing BVN."""
        data = {'nin': '12345678901'}
        response = self.client.post('/profile/v1/update-kyc/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UpdateVehicleInfoViewTestCase(APITestCase):
    """Test cases for UpdateVehicleInfoView."""
    
    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(email='vehicle@example.com', password='password123')
        self.user.is_email_verified = True
        self.user.save()
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
    
    def test_update_vehicle_success(self):
        """Test successful vehicle update."""
        data = {
            'vehicle_plate_number': 'ABC123',
            'vehicle_type': 'Car',
            'vehicle_brand': 'Toyota'
        }
        response = self.client.post('/profile/v1/update-vehicle/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class UpdatePersonalInfoViewTestCase(APITestCase):
    """Test cases for UpdatePersonalInfoView."""
    
    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(email='personal@example.com', password='password123')
        self.user.is_email_verified = True
        self.user.save()
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
    
    def test_update_personal_info_success(self):
        """Test successful personal info update."""
        data = {'first_name': 'John', 'last_name': 'Doe'}
        response = self.client.post('/profile/v1/update-personal-info/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class UpdateSubscriptionPlanViewTestCase(APITestCase):
    """Test cases for UpdateSubscriptionPlanView."""
    
    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(email='sub@example.com', password='password123')
        self.user.is_email_verified = True
        self.user.save()
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        self.plan = SubscriptionPlan.objects.create(name='basic', price=1200)
    
    def test_update_subscription_success(self):
        """Test successful subscription update."""
        data = {'plan_name': 'basic'}
        response = self.client.post('/profile/v1/update-subscription/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class NotificationModelTestCase(TestCase):
    """Test cases for Notification model."""
    
    def setUp(self):
        self.user = CustomUser.objects.create_user(email='notif@example.com', password='testpass123')
        self.notification = Notification.objects.create(
            user=self.user,
            title='Test Notification',
            message='This is a test message'
        )
    
    def test_notification_creation(self):
        """Test notification is created."""
        self.assertEqual(self.notification.title, 'Test Notification')
        self.assertFalse(self.notification.is_read)
    
    def test_mark_as_read(self):
        """Test marking notification as read."""
        self.notification.mark_as_read()
        self.assertTrue(self.notification.is_read)
    
    def test_get_unread_count(self):
        """Test getting unread notification count."""
        count = Notification.get_unread_count(self.user)
        self.assertEqual(count, 1)


class SocialMediaLinkModelTestCase(TestCase):
    """Test cases for SocialMediaLink model."""
    
    def setUp(self):
        self.user = CustomUser.objects.create_user(email='social@example.com', password='testpass123')
        self.social = SocialMediaLink.objects.create(
            user=self.user,
            facebook='https://facebook.com/test'
        )
    
    def test_social_link_creation(self):
        """Test social link is created."""
        self.assertEqual(self.social.facebook, 'https://facebook.com/test')


class GetNotificationsViewTestCase(APITestCase):
    """Test cases for GetNotificationsView."""
    
    def setUp(self):
        self.client = APIClient()
        self.user = CustomUser.objects.create_user(email='notifview@example.com', password='password123')
        self.user.is_email_verified = True
        self.user.save()
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        Notification.objects.create(user=self.user, title='Test', message='Test message')
    
    def test_get_notifications(self):
        """Test getting notifications."""
        response = self.client.get('/profile/v1/notifications/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)