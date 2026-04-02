from rest_framework import serializers
import logging

from .models import (
    KYC, SocialMediaLink, Vehicle, SubscriptionPlan, Subscription, 
    Badge, UserBadge, ReferralToken, Referral, Notification
)
from Auth.models import CustomUser

logger = logging.getLogger(__name__)


class KYCSerializer(serializers.ModelSerializer):
    """
    Serializer for KYC model with Cloudinary upload support.
    
    Handles KYC document uploads and validation including BVN format validation.
    """
    driver_license = serializers.SerializerMethodField()
    
    class Meta:
        model = KYC
        fields = ('user', 'nin', 'bvn', 'driver_license', 'verified', 'created_at', 'updated_at')
        read_only_fields = ('user', 'verified', 'created_at', 'updated_at')
    
    def get_driver_license(self, obj):
        """Get driver license URL."""
        return obj.driver_license if obj.driver_license else None
    
    def validate_bvn(self, value):
        """Validate BVN format - must be exactly 11 digits."""
        if value and len(str(value)) != 11:
            raise serializers.ValidationError("BVN must be exactly 11 digits.")
        return value
    
    def create(self, validated_data):
        """Create KYC with optional document uploads."""
        try:
            request = self.context.get('request')
            driver_license_file = None
            
            if request and request.FILES:
                driver_license_file = request.FILES.get('driver_license')
            
            if driver_license_file:
                from core.utils import upload_to_cloudinary
                driver_license_url = upload_to_cloudinary(driver_license_file)
                validated_data['driver_license'] = driver_license_url
            else:
                validated_data.pop('driver_license', None)
            
            kyc = super().create(validated_data)
            bvn = validated_data.get("bvn")
            
            if bvn:
                try:
                    from wallet.services import update_bvn_on_reserved_account
                    update_bvn_on_reserved_account(kyc.user, bvn)
                except ValueError as e:
                    raise serializers.ValidationError({"bvn": str(e)})
            
            logger.info(f"KYC created successfully for user: {kyc.user.email}")
            return kyc
        except Exception as e:
            logger.error(f"Error creating KYC: {str(e)}")
            raise serializers.ValidationError(f"Error creating KYC: {str(e)}")
    
    def update(self, instance, validated_data):
        """Update KYC with optional document uploads."""
        try:
            request = self.context.get('request')
            driver_license_file = None
            
            if request and request.FILES:
                driver_license_file = request.FILES.get('driver_license')
            
            old_bvn = instance.bvn
            
            if driver_license_file:
                from core.utils import upload_to_cloudinary
                driver_license_url = upload_to_cloudinary(driver_license_file)
                validated_data['driver_license'] = driver_license_url
            elif 'driver_license' in validated_data and validated_data['driver_license'] is None:
                pass
            else:
                validated_data.pop('driver_license', None)
            
            kyc = super().update(instance, validated_data)
            new_bvn = instance.bvn
            
            if new_bvn and new_bvn != old_bvn:
                try:
                    from wallet.services import update_bvn_on_reserved_account
                    update_bvn_on_reserved_account(instance.user, new_bvn)
                except ValueError as e:
                    raise serializers.ValidationError({"bvn": str(e)})
            
            logger.info(f"KYC updated successfully for user: {kyc.user.email}")
            return kyc
        except Exception as e:
            logger.error(f"Error updating KYC: {str(e)}")
            raise serializers.ValidationError(f"Error updating KYC: {str(e)}")


class SocialMediaLinkSerializer(serializers.ModelSerializer):
    """
    Serializer for SocialMediaLink model.
    """
    class Meta:
        model = SocialMediaLink
        fields = '__all__'
        read_only_fields = ('user', 'created_at', 'updated_at')


class VehicleSerializer(serializers.ModelSerializer):
    """
    Serializer for Vehicle model with optional document uploads.
    """
    class Meta:
        model = Vehicle
        fields = '__all__'
        read_only_fields = ('user', 'created_at', 'updated_at')
    
    def create(self, validated_data):
        """Create Vehicle with optional document uploads."""
        try:
            request = self.context.get('request')
            
            for field in ['vehicle_photo', 'driver_license', 'vehicle_inspector_report', 'vehicle_insurance']:
                if request and request.FILES:
                    file = request.FILES.get(field)
                    if file:
                        from core.utils import upload_to_cloudinary
                        validated_data[field] = upload_to_cloudinary(file)
                    else:
                        validated_data.pop(field, None)
            
            return super().create(validated_data)
        except Exception as e:
            logger.error(f"Error creating vehicle: {str(e)}")
            raise serializers.ValidationError(f"Error creating vehicle: {str(e)}")
    
    def update(self, instance, validated_data):
        """Update Vehicle with optional document uploads."""
        try:
            request = self.context.get('request')
            
            for field in ['vehicle_photo', 'driver_license', 'vehicle_inspector_report', 'vehicle_insurance']:
                if request and request.FILES:
                    file = request.FILES.get(field)
                    if file:
                        from core.utils import upload_to_cloudinary
                        validated_data[field] = upload_to_cloudinary(file)
                    elif field in validated_data and validated_data[field] is None:
                        pass
                    else:
                        validated_data.pop(field, None)
            
            return super().update(instance, validated_data)
        except Exception as e:
            logger.error(f"Error updating vehicle: {str(e)}")
            raise serializers.ValidationError(f"Error updating vehicle: {str(e)}")


class SubscriptionPlanSerializer(serializers.ModelSerializer):
    """
    Serializer for SubscriptionPlan model.
    """
    class Meta:
        model = SubscriptionPlan
        fields = '__all__'


class SubscriptionSerializer(serializers.ModelSerializer):
    """
    Serializer for Subscription model.
    """
    plan_name = serializers.CharField(source='plan.name', read_only=True)
    plan_price = serializers.DecimalField(source='plan.price', max_digits=10, decimal_places=2, read_only=True)
    
    class Meta:
        model = Subscription
        fields = ('id', 'user', 'plan', 'plan_name', 'plan_price', 'start_date', 'end_date', 'created_at', 'updated_at')
        read_only_fields = ('user', 'start_date', 'created_at', 'updated_at')


class BadgeSerializer(serializers.ModelSerializer):
    """
    Serializer for Badge model.
    """
    class Meta:
        model = Badge
        fields = '__all__'


class UserBadgeSerializer(serializers.ModelSerializer):
    """
    Serializer for UserBadge model.
    """
    badge_name = serializers.CharField(source='badge.name', read_only=True)
    badge_description = serializers.CharField(source='badge.description', read_only=True)
    
    class Meta:
        model = UserBadge
        fields = ('id', 'user', 'badge', 'badge_name', 'badge_description', 'awarded_at', 'created_at', 'updated_at')
        read_only_fields = ('user', 'awarded_at', 'created_at', 'updated_at')


class ReferralTokenSerializer(serializers.ModelSerializer):
    """
    Serializer for ReferralToken model.
    """
    class Meta:
        model = ReferralToken
        fields = '__all__'
        read_only_fields = ('user', 'token', 'created_at', 'updated_at')


class ReferralSerializer(serializers.ModelSerializer):
    """
    Serializer for Referral model.
    """
    referred_by_email = serializers.EmailField(source='referred_by.email', read_only=True)
    referred_user_email = serializers.EmailField(source='referred_user.email', read_only=True)
    
    class Meta:
        model = Referral
        fields = ('id', 'referred_by', 'referred_by_email', 'referred_user', 'referred_user_email', 'token_used', 'created_at', 'updated_at')
        read_only_fields = ('token_used', 'created_at', 'updated_at')


class NotificationSerializer(serializers.ModelSerializer):
    """
    Serializer for Notification model.
    """
    class Meta:
        model = Notification
        fields = ('id', 'user', 'title', 'message', 'is_read', 'created_at', 'updated_at')
        read_only_fields = ('user', 'created_at', 'updated_at')
    
    def create(self, validated_data):
        """Create notification with user from request context."""
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['user'] = request.user
        return super().create(validated_data)


class UserProfileSerializer(serializers.Serializer):
    """
    Serializer for complete user profile with related data.
    """
    email = serializers.EmailField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    phone_number = serializers.CharField()
    profile_picture = serializers.ImageField()
    is_email_verified = serializers.BooleanField()
    
    kyc = KYCSerializer(read_only=True)
    vehicle = VehicleSerializer(read_only=True)
    subscription = SubscriptionSerializer(read_only=True)
    social_media = SocialMediaLinkSerializer(read_only=True)
    notifications = NotificationSerializer(many=True, read_only=True)