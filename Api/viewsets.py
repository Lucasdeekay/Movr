from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from rest_framework.filters import SearchFilter, OrderingFilter

from .models import CustomUser, KYC, Notification, Vehicle, SubscriptionPlan, Subscription, OTP, SocialMediaLink, \
    Route, ScheduledRoute, Day, Badge, UserBadge, ReferralToken, Referral
from .serializers import CustomUserSerializer, KYCSerializer, NotificationSerializer, VehicleSerializer, \
    SubscriptionPlanSerializer, SubscriptionSerializer, OTPSerializer, SocialMediaLinkSerializer, RouteSerializer, \
    ScheduledRouteSerializer, DaySerializer, BadgeSerializer, UserBadgeSerializer, ReferralTokenSerializer, ReferralSerializer


class CustomUserViewSet(viewsets.ModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer

class KYCViewSet(viewsets.ModelViewSet):
    queryset = KYC.objects.all()
    serializer_class = KYCSerializer

class SocialMediaLinkViewSet(viewsets.ModelViewSet):
    queryset = SocialMediaLink.objects.all()
    serializer_class = SocialMediaLinkSerializer

class VehicleViewSet(viewsets.ModelViewSet):
    queryset = Vehicle.objects.all()
    serializer_class = VehicleSerializer

class SubscriptionPlanViewSet(viewsets.ModelViewSet):
    queryset = SubscriptionPlan.objects.all()
    serializer_class = SubscriptionPlanSerializer

class SubscriptionViewSet(viewsets.ModelViewSet):
    queryset = Subscription.objects.all()
    serializer_class = SubscriptionSerializer

class OTPViewSet(viewsets.ModelViewSet):
    queryset = OTP.objects.all()
    serializer_class = OTPSerializer

class RouteViewSet(viewsets.ModelViewSet):
    serializer_class = RouteSerializer
    queryset = Route.objects.all()
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class ScheduledRouteViewSet(viewsets.ModelViewSet):
    serializer_class = ScheduledRouteSerializer
    queryset = ScheduledRoute.objects.all()
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        route_data = serializer.validated_data['route']
        route_data['user'] = self.request.user
        serializer.save()


class DayViewSet(viewsets.ModelViewSet):
    serializer_class = DaySerializer
    queryset = Day.objects.all()
    permission_classes = [IsAuthenticated]

class BadgeViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing badges.
    """
    queryset = Badge.objects.all()
    serializer_class = BadgeSerializer
    permission_classes = [IsAuthenticated]  # Adjust permissions as needed

class UserBadgeViewSet(viewsets.ModelViewSet):
    """
    A viewset for managing user badges.
    """
    serializer_class = UserBadgeSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Ensure users can only see their own badges
        return UserBadge.objects.filter(user=self.request.user)

class ReferralTokenViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing referral tokens.
    """
    queryset = ReferralToken.objects.all()
    serializer_class = ReferralTokenSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ReferralToken.objects.filter(user=self.request.user)

class ReferralViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing referrals.
    """
    queryset = Referral.objects.all()
    serializer_class = ReferralSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Referral.objects.filter(referred_by=self.request.user)

class NotificationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Notification model.
    
    Provides CRUD operations for notifications with user-specific filtering.
    """
    serializer_class = NotificationSerializer
    filter_backends = (SearchFilter, OrderingFilter)
    filterset_fields = ['is_read', 'created_at']
    search_fields = ['title', 'message']
    ordering_fields = ['created_at', 'is_read']
    ordering = ['-created_at']
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Return notifications for the authenticated user only."""
        return Notification.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        """Log notification creation."""
        notification = serializer.save()

    def perform_update(self, serializer):
        """Log notification updates."""
        notification = serializer.save()

    def perform_destroy(self, instance):
        """Log notification deletion."""
        user_email = instance.user.email
        instance.delete()
