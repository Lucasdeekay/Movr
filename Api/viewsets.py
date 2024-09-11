from rest_framework import viewsets
from .models import CustomUser, KYC, Vehicle, PaymentMethod, SubscriptionPlan, Subscription, OTP, SocialMediaLink
from .serializers import CustomUserSerializer, KYCSerializer, VehicleSerializer, PaymentMethodSerializer, \
    SubscriptionPlanSerializer, SubscriptionSerializer, OTPSerializer, SocialMediaLinkSerializer


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
