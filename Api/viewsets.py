from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import CustomUser, KYC, Vehicle, PaymentMethod, SubscriptionPlan, Subscription, OTP, SocialMediaLink, \
    Route, ScheduledRoute, Day, Wallet, Transaction, Transfer, WithdrawalRequest
from .serializers import CustomUserSerializer, KYCSerializer, VehicleSerializer, PaymentMethodSerializer, \
    SubscriptionPlanSerializer, SubscriptionSerializer, OTPSerializer, SocialMediaLinkSerializer, RouteSerializer, \
    ScheduledRouteSerializer, DaySerializer, WalletSerializer, TransactionSerializer, TransferSerializer, \
    WithdrawalRequestSerializer


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

class PaymentMethodViewSet(viewsets.ModelViewSet):
    queryset = PaymentMethod.objects.all()
    serializer_class = PaymentMethodSerializer

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


class WalletViewSet(viewsets.ModelViewSet):
    """
    ViewSet to manage Wallet operations.
    """
    serializer_class = WalletSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Wallet.objects.filter(user=self.request.user)


class TransactionViewSet(viewsets.ModelViewSet):
    """
    ViewSet to manage user transactions.
    """
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Transaction.objects.filter(user=self.request.user).order_by("-timestamp")

class TransferViewSet(viewsets.ModelViewSet):
    """
    ViewSet to manage transfers between users.
    """
    serializer_class = TransferSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Transfer.objects.filter(sender=self.request.user).order_by("-timestamp")


class WithdrawalRequestViewSet(viewsets.ModelViewSet):
    queryset = WithdrawalRequest.objects.all()
    serializer_class = WithdrawalRequestSerializer


# from rest_framework import viewsets
# from .models import (
#     User, UserProfile, PaymentMethod, SubscriptionPlan, Subscription,
#     TravelPlan, RideMatch, RideTracking, Insurance, DamageReport,
#     KYC, HomeAwayStatus, SOSAlert, SocialLink, Badge, UserBadge, Review
# )
# from .serializers import (
#     UserSerializer, UserProfileSerializer, PaymentMethodSerializer, SubscriptionPlanSerializer,
#     SubscriptionSerializer, TravelPlanSerializer, RideMatchSerializer, RideTrackingSerializer,
#     InsuranceSerializer, DamageReportSerializer, KYCSerializer, HomeAwayStatusSerializer,
#     SOSAlertSerializer, SocialLinkSerializer, BadgeSerializer, UserBadgeSerializer, ReviewSerializer
# )
#
# # User and Profile ViewSets
# class UserViewSet(viewsets.ModelViewSet):
#     queryset = User.objects.all()
#     serializer_class = UserSerializer
#
# class UserProfileViewSet(viewsets.ModelViewSet):
#     queryset = UserProfile.objects.all()
#     serializer_class = UserProfileSerializer
#
# # Payment ViewSets
# class PaymentMethodViewSet(viewsets.ModelViewSet):
#     queryset = PaymentMethod.objects.all()
#     serializer_class = PaymentMethodSerializer
#
# class SubscriptionPlanViewSet(viewsets.ModelViewSet):
#     queryset = SubscriptionPlan.objects.all()
#     serializer_class = SubscriptionPlanSerializer
#
# class SubscriptionViewSet(viewsets.ModelViewSet):
#     queryset = Subscription.objects.all()
#     serializer_class = SubscriptionSerializer
#
# # Travel and Ride ViewSets
# class TravelPlanViewSet(viewsets.ModelViewSet):
#     queryset = TravelPlan.objects.all()
#     serializer_class = TravelPlanSerializer
#
# class RideMatchViewSet(viewsets.ModelViewSet):
#     queryset = RideMatch.objects.all()
#     serializer_class = RideMatchSerializer
#
# class RideTrackingViewSet(viewsets.ModelViewSet):
#     queryset = RideTracking.objects.all()
#     serializer_class = RideTrackingSerializer
#
# # Delivery ViewSets
# class InsuranceViewSet(viewsets.ModelViewSet):
#     queryset = Insurance.objects.all()
#     serializer_class = InsuranceSerializer
#
# class DamageReportViewSet(viewsets.ModelViewSet):
#     queryset = DamageReport.objects.all()
#     serializer_class = DamageReportSerializer
#
# # Safety ViewSets
# class KYCViewSet(viewsets.ModelViewSet):
#     queryset = KYC.objects.all()
#     serializer_class = KYCSerializer
#
# class HomeAwayStatusViewSet(viewsets.ModelViewSet):
#     queryset = HomeAwayStatus.objects.all()
#     serializer_class = HomeAwayStatusSerializer
#
# class SOSAlertViewSet(viewsets.ModelViewSet):
#     queryset = SOSAlert.objects.all()
#     serializer_class = SOSAlertSerializer
#
#
# class BadgeViewSet(viewsets.ModelViewSet):
#     queryset = Badge.objects.all()
#     serializer_class = BadgeSerializer
#
# class UserBadgeViewSet(viewsets.ModelViewSet):
#     queryset = UserBadge.objects.all()
#     serializer_class = UserBadgeSerializer
#
# class ReviewViewSet(viewsets.ModelViewSet):
#     queryset = Review.objects.all()
#     serializer_class = ReviewSerializer
