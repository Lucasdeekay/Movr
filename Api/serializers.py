from rest_framework import serializers
from rest_framework.authtoken.models import Token

from .models import CustomUser, KYC, Vehicle, PaymentMethod, SubscriptionPlan, Subscription, OTP, SocialMediaLink, \
    Route, ScheduledRoute, Day, Package, Bid, QRCode, PackageOffer


class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = ('key',)

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = '__all__'

class KYCSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)

    class Meta:
        model = KYC
        fields = '__all__'

class SocialMediaLinkSerializer(serializers.ModelSerializer):
    class Meta:
        model = SocialMediaLink
        fields = '__all__'

class VehicleSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)

    class Meta:
        model = Vehicle
        fields = '__all__'

class PaymentMethodSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)

    class Meta:
        model = PaymentMethod
        fields = '__all__'

class SubscriptionPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = '__all__'

class SubscriptionSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)
    plan = SubscriptionPlanSerializer(read_only=True)

    class Meta:
        model = Subscription
        fields = '__all__'

class OTPSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)

    class Meta:
        model = OTP
        fields = '__all__'

class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField()

    def validate(self, data):
        try:
            otp = OTP.objects.get(user__email=data['email'], code=data['code'])
            if otp.is_expired():
                raise serializers.ValidationError("OTP has expired")
            if otp.is_used:
                raise serializers.ValidationError("OTP has already been used")
            return data
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP")


class RouteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Route
        fields = '__all__'


class ScheduledRouteSerializer(serializers.ModelSerializer):
    route = RouteSerializer()
    days_of_week = serializers.SlugRelatedField(many=True, slug_field='name', queryset=Day.objects.all())

    class Meta:
        model = ScheduledRoute
        fields = '__all__'

    def create(self, validated_data):
        route_data = validated_data.pop('route')
        days_data = validated_data.pop('days_of_week')
        route = Route.objects.create(**route_data)
        scheduled_route = ScheduledRoute.objects.create(route=route, **validated_data)
        scheduled_route.days_of_week.set(days_data)
        return scheduled_route


class DaySerializer(serializers.ModelSerializer):
    class Meta:
        model = Day
        fields = '__all__'

class PackageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Package
        fields = '__all__'
        extra_kwargs = {
            'user': {'read_only': True},  # Make the 'user' field read-only
        }

class BidSerializer(serializers.ModelSerializer):
    mover_details = serializers.SerializerMethodField()

    class Meta:
        model = Bid
        fields = ['id', 'price', 'mover_details', 'created_at']

    def get_mover_details(self, obj):
        return {
            "name": f"{obj.mover.first_name} {obj.mover.last_name}",
            "email": obj.mover.email,
        }

class QRCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = QRCode
        fields = '__all__'


class PackageOfferSerializer(serializers.ModelSerializer):
    class Meta:
        model = PackageOffer
        fields = '__all__'




# from rest_framework import serializers
# from .models import (
#     User, UserProfile, PaymentMethod, SubscriptionPlan, Subscription,
#     TravelPlan, RideMatch, RideTracking, Insurance, DamageReport,
#     KYC, HomeAwayStatus, SOSAlert, SocialLink, Badge, UserBadge, Review
# )
#
# # User and Profile Serializers
# class UserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = '__all__'
#
# class UserProfileSerializer(serializers.ModelSerializer):
#     user = UserSerializer()
#
#     class Meta:
#         model = UserProfile
#         fields = '__all__'
#
# # Payment Serializers
# class PaymentMethodSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = PaymentMethod
#         fields = '__all__'
#
# class SubscriptionPlanSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = SubscriptionPlan
#         fields = '__all__'
#
# class SubscriptionSerializer(serializers.ModelSerializer):
#     plan = SubscriptionPlanSerializer()
#
#     class Meta:
#         model = Subscription
#         fields = '__all__'
#
# # Travel and Ride Serializers
# class TravelPlanSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = TravelPlan
#         fields = '__all__'
#
# class RideMatchSerializer(serializers.ModelSerializer):
#     travel_plan = TravelPlanSerializer()
#
#     class Meta:
#         model = RideMatch
#         fields = '__all__'
#
# class RideTrackingSerializer(serializers.ModelSerializer):
#     ride_match = RideMatchSerializer()
#
#     class Meta:
#         model = RideTracking
#         fields = '__all__'
#
# # Delivery Serializers
# class InsuranceSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Insurance
#         fields = '__all__'
#
# class DamageReportSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = DamageReport
#         fields = '__all__'
#
# # Safety Serializers
# class KYCSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = KYC
#         fields = '__all__'
#
# class HomeAwayStatusSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = HomeAwayStatus
#         fields = '__all__'
#
# class SOSAlertSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = SOSAlert
#         fields = '__all__'
#
#
# class BadgeSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Badge
#         fields = '__all__'
#
# class UserBadgeSerializer(serializers.ModelSerializer):
#     badge = BadgeSerializer()
#
#     class Meta:
#         model = UserBadge
#         fields = '__all__'
#
# class ReviewSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Review
#         fields = '__all__'
