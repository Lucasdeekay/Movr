from rest_framework import serializers
from rest_framework.authtoken.models import Token
from decimal import Decimal

from .models import CustomUser, KYC, Vehicle, PaymentMethod, SubscriptionPlan, Subscription, OTP, SocialMediaLink, \
    Route, ScheduledRoute, Day, Package, Bid, QRCode, PackageOffer, Wallet, Transaction, Transfer, WithdrawalRequest, \
    Badge, UserBadge, ReferralToken, Referral, PaystackAccount, PaystackTransaction


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

# Paystack Serializers
class PaystackAccountSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)
    
    class Meta:
        model = PaystackAccount
        fields = [
            'id', 'user', 'account_type', 'account_number', 'bank_name', 
            'bank_code', 'status', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user', 'account_number', 'bank_name', 'bank_code', 
            'paystack_customer_code', 'paystack_account_id', 'status', 
            'is_active', 'created_at', 'updated_at'
        ]


class PaystackTransactionSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)
    
    class Meta:
        model = PaystackTransaction
        fields = [
            'id', 'user', 'transaction_type', 'paystack_reference', 
            'paystack_transaction_id', 'amount', 'currency', 'status',
            'gateway_response', 'channel', 'ip_address', 'narration',
            'fees', 'paid_at', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user', 'paystack_reference', 'paystack_transaction_id',
            'gateway_response', 'channel', 'ip_address', 'fees', 
            'paid_at', 'created_at', 'updated_at'
        ]


class CreatePaystackAccountSerializer(serializers.Serializer):
    """
    Serializer for creating Paystack DVA account
    """
    preferred_bank = serializers.CharField(required=False, allow_blank=True)


class PaystackDepositSerializer(serializers.Serializer):
    """
    Serializer for Paystack deposit
    """
    amount = serializers.DecimalField(max_digits=12, decimal_places=2, min_value=Decimal('100.00'))
    email = serializers.EmailField()
    reference = serializers.CharField(required=False, allow_blank=True)
    callback_url = serializers.URLField(required=False, allow_blank=True)


class PaystackWithdrawalSerializer(serializers.Serializer):
    """
    Serializer for Paystack withdrawal
    """
    amount = serializers.DecimalField(max_digits=12, decimal_places=2, min_value=Decimal('100.00'))
    bank_code = serializers.CharField(max_length=10)
    account_number = serializers.CharField(max_length=20)
    account_name = serializers.CharField(max_length=100)
    narration = serializers.CharField(required=False, allow_blank=True)


class BankSerializer(serializers.Serializer):
    """
    Serializer for bank information
    """
    id = serializers.IntegerField()
    name = serializers.CharField()
    code = serializers.CharField()
    active = serializers.BooleanField()
    country = serializers.CharField()
    currency = serializers.CharField()
    type = serializers.CharField()


class ResolveAccountSerializer(serializers.Serializer):
    """
    Serializer for resolving account number
    """
    account_number = serializers.CharField(max_length=20)
    bank_code = serializers.CharField(max_length=10)


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


class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ["id", "user", "balance"]
        read_only_fields = ["id", "user", "balance"]

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ["id", "user", "transaction_type", "amount", "timestamp", "description"]
        read_only_fields = ["id", "user", "timestamp"]

class TransferSerializer(serializers.ModelSerializer):
    sender = serializers.StringRelatedField(read_only=True)
    recipient = serializers.StringRelatedField()

    class Meta:
        model = Transfer
        fields = ["id", "sender", "recipient", "amount", "timestamp", "message"]
        read_only_fields = ["id", "sender", "timestamp"]


class WithdrawalRequestSerializer(serializers.ModelSerializer):
    """
    Serializer for the WithdrawalRequest model.
    """
    class Meta:
        model = WithdrawalRequest
        fields = [
            'id',
            'user',
            'amount',
            'bank_name',
            'account_number',
            'status',
            'reason',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['id', 'user', 'status', 'reason', 'created_at', 'updated_at']


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

