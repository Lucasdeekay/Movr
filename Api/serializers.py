from rest_framework import serializers
from rest_framework.authtoken.models import Token
from decimal import Decimal

from Api.utils import upload_to_cloudinary
from wallet.services import update_bvn_on_reserved_account

from .models import CustomUser, KYC, Notification, Vehicle, SubscriptionPlan, Subscription, OTP, SocialMediaLink, \
    Route, ScheduledRoute, Day, Package, Bid, QRCode, PackageOffer, \
    Badge, UserBadge, ReferralToken, Referral

import logging

logger = logging.getLogger(__name__)

class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = ('key',)

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = '__all__'

class KYCSerializer(serializers.ModelSerializer):
    """
    Serializer for KYC model.
    
    Handles KYC document uploads and validation including
    national ID, driver license, and proof of address.
    """
    national_id = serializers.SerializerMethodField()
    driver_license = serializers.SerializerMethodField()
    class Meta:
        model = KYC
        fields = (
            'user', 'national_id', 'bvn', 'driver_license', 'proof_of_address',
            'status', 'updated_at', 'verified_at'
        )
        read_only_fields = ('updated_at', 'verified_at')

    def validate_bvn(self, value):
        """
        Validate BVN format.
        
        Ensures BVN is exactly 11 digits.
        """
        if value and len(str(value)) != 11:
            raise serializers.ValidationError("BVN must be exactly 11 digits.")
        return value

    def create(self, validated_data):
        """
        Create a new KYC instance.
        
        Handles document uploads to Cloudinary.
        """
        try:
            request = self.context.get('request')

            # Handle national_id upload
            national_id_file = None
            if request and request.FILES:
                national_id_file = request.FILES.get('national_id')
            if national_id_file:
                national_id_url = upload_to_cloudinary(national_id_file)
                validated_data['national_id'] = national_id_url
            else:
                validated_data.pop('national_id', None)

            # Handle driver_license upload
            driver_license_file = None
            if request and request.FILES:
                driver_license_file = request.FILES.get('driver_license')
            if driver_license_file:
                driver_license_url = upload_to_cloudinary(driver_license_file)
                validated_data['driver_license'] = driver_license_url
            else:
                validated_data.pop('driver_license', None)

            kyc = super().create(validated_data)
            bvn = validated_data.get("bvn")

            if bvn:
                try:
                    update_bvn_on_reserved_account(kyc.user, bvn)
                except ValueError as e:
                    # surface the error but do NOT roll back KYC
                    raise serializers.ValidationError({"bvn": str(e)})
            logger.info(f"KYC created successfully for user: {kyc.user.email}")
            return kyc
            
        except Exception as e:
            logger.error(f"Error creating KYC: {str(e)}")
            raise serializers.ValidationError(f"Error creating KYC: {str(e)}")

    def update(self, instance, validated_data):
        """
        Update an existing KYC instance.
        
        Handles document uploads to Cloudinary.
        """
        try:
            request = self.context.get('request')

            # Handle national_id upload
            national_id_file = None
            if request and request.FILES:
                national_id_file = request.FILES.get('national_id')
            if national_id_file:
                national_id_url = upload_to_cloudinary(national_id_file)
                validated_data['national_id'] = national_id_url
            elif 'national_id' in validated_data and validated_data['national_id'] is None:
                pass
            else:
                validated_data.pop('national_id', None)

            # Handle driver_license upload
            driver_license_file = None
            if request and request.FILES:
                driver_license_file = request.FILES.get('driver_license')
            if driver_license_file:
                driver_license_url = upload_to_cloudinary(driver_license_file)
                validated_data['driver_license'] = driver_license_url
            elif 'driver_license' in validated_data and validated_data['driver_license'] is None:
                pass
            else:
                validated_data.pop('driver_license', None)

            kyc = super().update(instance, validated_data)
            old_bvn = instance.bvn
            instance = super().update(instance, validated_data)
            new_bvn = instance.bvn

            if new_bvn and new_bvn != old_bvn:
                try:
                    update_bvn_on_reserved_account(instance.user, new_bvn)
                except ValueError as e:
                    raise serializers.ValidationError({"bvn": str(e)})
            logger.info(f"KYC updated successfully for user: {kyc.user.email}")
            
        except Exception as e:
            logger.error(f"Error updating KYC: {str(e)}")
            raise serializers.ValidationError(f"Error updating KYC: {str(e)}")

    def get_national_id(self, obj):
        """
        Get national ID URL.
        
        Returns the national ID URL if it exists, otherwise None.
        """
        return obj.national_id if obj.national_id else None

    def get_driver_license(self, obj):
        """
        Get driver license URL.
        
        Returns the driver license URL if it exists, otherwise None.
        """
        return obj.driver_license if obj.driver_license else None

    def get_proof_of_address(self, obj):
        """
        Get proof of address URL.
        
        Returns the proof of address URL if it exists, otherwise None.
        """
        return obj.proof_of_address if obj.proof_of_address else None

class SocialMediaLinkSerializer(serializers.ModelSerializer):
    class Meta:
        model = SocialMediaLink
        fields = '__all__'

class VehicleSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)

    class Meta:
        model = Vehicle
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


class BadgeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Badge
        fields = ['id', 'name', 'description', 'icon', 'criteria']


class UserBadgeSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)  # Or use a nested serializer for more details
    badge = BadgeSerializer(read_only=True)

    class Meta:
        model = UserBadge
        fields = ['id', 'user', 'badge', 'awarded_at']


class ReferralTokenSerializer(serializers.ModelSerializer):
    """
    Serializer for ReferralToken model.
    """
    class Meta:
        model = ReferralToken
        fields = ['user', 'token', 'created_at']
        read_only_fields = ['token', 'created_at']


class ReferralSerializer(serializers.ModelSerializer):
    """
    Serializer for Referral model.
    """
    referred_by_username = serializers.CharField(
        source='referred_by.username', read_only=True
    )
    referred_user_username = serializers.CharField(
        source='referred_user.username', read_only=True
    )

    class Meta:
        model = Referral
        fields = [
            'referred_by', 'referred_user', 'token_used',
            'created_at', 'referred_by_username', 'referred_user_username'
        ]
        read_only_fields = ['created_at']

class NotificationSerializer(serializers.ModelSerializer):
    """
    Serializer for Notification model.
    
    Handles notification data serialization and deserialization including
    message content, read status, and user association.
    """
    
    class Meta:
        model = Notification
        fields = ('id', 'user', 'title', 'message', 'created_at', 'is_read')
        read_only_fields = ('id', 'created_at')
        extra_kwargs = {
            'user': {'required': True},
            'message': {'required': True},
            'title': {'required': False}
        }

    def validate_message(self, value):
        """
        Validate message content.
        
        Ensures message is not empty and has reasonable length.
        """
        if not value or not value.strip():
            raise serializers.ValidationError("Message cannot be empty.")
        
        if len(value) > 1000:
            raise serializers.ValidationError("Message is too long. Maximum 1000 characters.")
        
        return value.strip()

    def validate_title(self, value):
        """
        Validate title content.
        
        Ensures title has reasonable length if provided.
        """
        if value and len(value) > 200:
            raise serializers.ValidationError("Title is too long. Maximum 200 characters.")
        
        return value.strip() if value else value

    def create(self, validated_data):
        """
        Create a new notification instance.
        
        Handles notification creation with proper validation.
        """
        try:
            notification = super().create(validated_data)
            logger.info(f"Notification created for user: {notification.user.email}")
            return notification
            
        except Exception as e:
            logger.error(f"Error creating notification: {str(e)}")
            raise serializers.ValidationError(f"Error creating notification: {str(e)}")

    def update(self, instance, validated_data):
        """
        Update an existing notification instance.
        
        Handles notification updates with proper validation.
        """
        try:
            notification = super().update(instance, validated_data)
            logger.info(f"Notification updated for user: {notification.user.email}")
            return notification
            
        except Exception as e:
            logger.error(f"Error updating notification: {str(e)}")
            raise serializers.ValidationError(f"Error updating notification: {str(e)}")


class NotificationListSerializer(serializers.ModelSerializer):
    """
    Serializer for listing notifications.
    
    Provides a simplified view of notifications for list endpoints
    with optimized field selection.
    """
    
    class Meta:
        model = Notification
        fields = ('id', 'title', 'message', 'created_at', 'is_read')
        read_only_fields = ('id', 'created_at')


class NotificationDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for detailed notification view.
    
    Provides comprehensive notification information including
    user details and full message content.
    """
    
    user_email = serializers.ReadOnlyField(source='user.email')
    user_name = serializers.SerializerMethodField()
    
    class Meta:
        model = Notification
        fields = (
            'id', 'user', 'user_email', 'user_name', 'title', 'message', 
            'created_at', 'is_read'
        )
        read_only_fields = ('id', 'created_at', 'user_email', 'user_name')

    def get_user_name(self, obj):
        """
        Get user's full name.
        
        Returns the user's full name or email if name is not available.
        """
        return obj.user.get_full_name() if obj.user else None
