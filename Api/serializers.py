from rest_framework import serializers
from rest_framework.authtoken.models import Token

from .models import CustomUser, KYC, Vehicle, PaymentMethod, SubscriptionPlan, Subscription, OTP, SocialMediaLink


class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = ('key',)

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'first_name', 'last_name', 'phone_number', 'is_email_verified', 'profile_picture', 'two_factor_enabled', 'date_joined']

class KYCSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)

    class Meta:
        model = KYC
        fields = ['user', 'bvn', 'nin', 'verified']

class SocialMediaLinkSerializer(serializers.ModelSerializer):
    class Meta:
        model = SocialMediaLink
        fields = '__all__'

class VehicleSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)

    class Meta:
        model = Vehicle
        fields = ['user', 'vehicle_plate_number', 'vehicle_type', 'vehicle_brand', 'vehicle_color', 'vehicle_photo', 'driver_license', 'vehicle_inspector_report', 'vehicle_insurance']

class PaymentMethodSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)

    class Meta:
        model = PaymentMethod
        fields = ['user', 'method_name', 'account_details']

class SubscriptionPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = ['id', 'name', 'description', 'price', 'duration']

class SubscriptionSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)
    plan = SubscriptionPlanSerializer(read_only=True)

    class Meta:
        model = Subscription
        fields = ['user', 'plan', 'start_date', 'end_date']

class OTPSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)

    class Meta:
        model = OTP
        fields = ['user', 'code', 'is_used', 'created_at', 'expires_at']

class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    phone_number = serializers.CharField()
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
