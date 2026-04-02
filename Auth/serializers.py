from rest_framework import serializers
from rest_framework.authtoken.models import Token

from .models import CustomUser, OTP
from Profile.models import Notification


class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = ('key',)


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
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


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = '__all__'
