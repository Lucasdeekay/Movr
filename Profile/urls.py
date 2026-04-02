from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .models import KYC, Vehicle, SubscriptionPlan, Subscription, Notification, Badge, UserBadge, ReferralToken, Referral, SocialMediaLink
from .serializers import (
    KYCSerializer, VehicleSerializer, SubscriptionPlanSerializer, SubscriptionSerializer,
    NotificationSerializer, BadgeSerializer, UserBadgeSerializer, ReferralTokenSerializer, 
    ReferralSerializer, SocialMediaLinkSerializer
)
from rest_framework import viewsets
from .views import (
    UpdateKYCView, UpdateVehicleInfoView, ProfileImageUploadView, 
    UpdatePersonalInfoView, UpdateSubscriptionPlanView, GetNotificationsView,
    MarkNotificationAsReadView, UpdateSocialMediaLinkView
)
from drf_spectacular.utils import extend_schema


class KYCViewSet(viewsets.ModelViewSet):
    """ViewSet for KYC model operations."""
    queryset = KYC.objects.all()
    serializer_class = KYCSerializer


class VehicleViewSet(viewsets.ModelViewSet):
    """ViewSet for Vehicle model operations."""
    queryset = Vehicle.objects.all()
    serializer_class = VehicleSerializer


class SubscriptionPlanViewSet(viewsets.ModelViewSet):
    """ViewSet for SubscriptionPlan model operations."""
    queryset = SubscriptionPlan.objects.all()
    serializer_class = SubscriptionPlanSerializer


class SubscriptionViewSet(viewsets.ModelViewSet):
    """ViewSet for Subscription model operations."""
    queryset = Subscription.objects.all()
    serializer_class = SubscriptionSerializer


class NotificationViewSet(viewsets.ModelViewSet):
    """ViewSet for Notification model operations."""
    queryset = Notification.objects.all()
    serializer_class = NotificationSerializer


class BadgeViewSet(viewsets.ModelViewSet):
    """ViewSet for Badge model operations."""
    queryset = Badge.objects.all()
    serializer_class = BadgeSerializer


class UserBadgeViewSet(viewsets.ModelViewSet):
    """ViewSet for UserBadge model operations."""
    queryset = UserBadge.objects.all()
    serializer_class = UserBadgeSerializer


class ReferralTokenViewSet(viewsets.ModelViewSet):
    """ViewSet for ReferralToken model operations."""
    queryset = ReferralToken.objects.all()
    serializer_class = ReferralTokenSerializer


class ReferralViewSet(viewsets.ModelViewSet):
    """ViewSet for Referral model operations."""
    queryset = Referral.objects.all()
    serializer_class = ReferralSerializer


class SocialMediaLinkViewSet(viewsets.ModelViewSet):
    """ViewSet for SocialMediaLink model operations."""
    queryset = SocialMediaLink.objects.all()
    serializer_class = SocialMediaLinkSerializer


router = DefaultRouter()
router.register(r'kyc', KYCViewSet, basename='kyc')
router.register(r'vehicles', VehicleViewSet, basename='vehicle')
router.register(r'subscription-plans', SubscriptionPlanViewSet, basename='subscription-plan')
router.register(r'subscriptions', SubscriptionViewSet, basename='subscription')
router.register(r'notifications', NotificationViewSet, basename='notification')
router.register(r'badges', BadgeViewSet, basename='badge')
router.register(r'user-badges', UserBadgeViewSet, basename='user-badge')
router.register(r'referral-tokens', ReferralTokenViewSet, basename='referral-token')
router.register(r'referrals', ReferralViewSet, basename='referral')
router.register(r'social-media', SocialMediaLinkViewSet, basename='social-media')


urlpatterns = [
    # Profile management endpoints
    path('update-kyc/', UpdateKYCView.as_view(), name='update-kyc'),
    path('update-vehicle/', UpdateVehicleInfoView.as_view(), name='update-vehicle'),
    path('upload-profile-image/', ProfileImageUploadView.as_view(), name='upload-profile-image'),
    path('update-personal-info/', UpdatePersonalInfoView.as_view(), name='update-personal-info'),
    path('update-subscription/', UpdateSubscriptionPlanView.as_view(), name='update-subscription'),
    path('notifications/', GetNotificationsView.as_view(), name='notifications'),
    path('notifications/<uuid:notification_id>/mark-read/', MarkNotificationAsReadView.as_view(), name='mark-notification-read'),
    path('social-media/', UpdateSocialMediaLinkView.as_view(), name='social-media'),
    
    # API endpoints
    path('api/', include(router.urls)),
]