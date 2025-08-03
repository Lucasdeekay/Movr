from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import CustomUser, KYC, Vehicle, PaymentMethod, SubscriptionPlan, Subscription, OTP, SocialMediaLink, \
    Route, ScheduledRoute, Day, Wallet, Transaction, Transfer, WithdrawalRequest, Badge, UserBadge, ReferralToken, \
    Referral, PaystackAccount, PaystackTransaction
from .serializers import CustomUserSerializer, KYCSerializer, VehicleSerializer, PaymentMethodSerializer, \
    SubscriptionPlanSerializer, SubscriptionSerializer, OTPSerializer, SocialMediaLinkSerializer, RouteSerializer, \
    ScheduledRouteSerializer, DaySerializer, WalletSerializer, TransactionSerializer, TransferSerializer, \
    WithdrawalRequestSerializer, BadgeSerializer, UserBadgeSerializer, ReferralTokenSerializer, ReferralSerializer, \
    PaystackAccountSerializer, PaystackTransactionSerializer


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

# Paystack Viewsets
class PaystackAccountViewSet(viewsets.ModelViewSet):
    """
    ViewSet to manage Paystack accounts.
    """
    serializer_class = PaystackAccountSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return PaystackAccount.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class PaystackTransactionViewSet(viewsets.ModelViewSet):
    """
    ViewSet to manage Paystack transactions.
    """
    serializer_class = PaystackTransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return PaystackTransaction.objects.filter(user=self.request.user).order_by('-created_at')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


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
        return Transfer.objects.filter(sender=self.request.user) | Transfer.objects.filter(recipient=self.request.user)

class WithdrawalRequestViewSet(viewsets.ModelViewSet):
    queryset = WithdrawalRequest.objects.all()
    serializer_class = WithdrawalRequestSerializer

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

