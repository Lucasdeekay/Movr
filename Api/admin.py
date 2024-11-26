from django.contrib import admin
from .models import CustomUser, KYC, Vehicle, PaymentMethod, SubscriptionPlan, Subscription, OTP, SocialMediaLink, \
    Route, ScheduledRoute, Day, Package, Bid, QRCode, PackageOffer, Wallet, Transaction, Transfer, WithdrawalRequest, \
    Badge, UserBadge, ReferralToken, Referral


@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('email', 'first_name', 'last_name', 'phone_number', 'is_email_verified', 'two_factor_enabled', 'date_joined')
    search_fields = ('email', 'first_name', 'last_name', 'phone_number')
    list_filter = ('is_email_verified', 'two_factor_enabled', 'date_joined')

@admin.register(KYC)
class KYCAdmin(admin.ModelAdmin):
    list_display = ('user', 'bvn', 'nin', 'verified')
    search_fields = ('user__email', 'bvn', 'nin')
    list_filter = ('verified',)

# Social and Badge Admin
@admin.register(SocialMediaLink)
class SocialMediaLinkAdmin(admin.ModelAdmin):
    list_display = ('user', 'facebook', 'instagram', 'linkedin')
    search_fields = ('user__username',)

@admin.register(Vehicle)
class VehicleAdmin(admin.ModelAdmin):
    list_display = ('user', 'vehicle_plate_number', 'vehicle_type', 'vehicle_brand', 'vehicle_color')
    search_fields = ('user__email', 'vehicle_plate_number', 'vehicle_brand')
    list_filter = ('vehicle_type',)

@admin.register(PaymentMethod)
class PaymentMethodAdmin(admin.ModelAdmin):
    list_display = ('user', 'method_name', 'account_details')
    search_fields = ('user__email', 'method_name')

@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = ('name', 'price', 'duration')
    search_fields = ('name',)
    list_filter = ('price',)

@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ('user', 'plan', 'start_date', 'end_date')
    search_fields = ('user__email', 'plan__name')
    list_filter = ('start_date', 'end_date')

@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'code', 'is_used', 'created_at', 'expires_at')
    search_fields = ('user__email', 'code')
    list_filter = ('is_used', 'created_at', 'expires_at')

@admin.register(Route)
class RouteAdmin(admin.ModelAdmin):
    list_display = ('user', 'title', 'location', 'destination', 'transportation_mode', 'service_type', 'departure_time', 'is_live')
    search_fields = ('user__email', 'title', 'location', 'destination', 'transportation_mode')
    list_filter = ('transportation_mode', 'service_type', 'is_live')
    ordering = ('-departure_time',)

@admin.register(ScheduledRoute)
class ScheduledRouteAdmin(admin.ModelAdmin):
    list_display = ('route', 'is_returning', 'is_repeated', 'returning_time')
    search_fields = ('route__user__email', 'route__location', 'route__destination')
    list_filter = ('is_returning', 'is_repeated')
    ordering = ('-route__departure_time',)

@admin.register(Day)
class DayAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)
    ordering = ('name',)


@admin.register(Package)
class PackageAdmin(admin.ModelAdmin):
    list_display = ('user', 'location', 'destination', 'item_weight', 'range_radius')
    search_fields = ('user__email', 'location', 'destination')
    list_filter = ('item_weight', 'range_radius')

@admin.register(Bid)
class BidAdmin(admin.ModelAdmin):
    list_display = ('package', 'mover', 'price', 'created_at')
    search_fields = ('mover__email', 'package__location', 'package__destination')
    list_filter = ('created_at',)

@admin.register(QRCode)
class QRCodeAdmin(admin.ModelAdmin):
    list_display = ('code',)
    search_fields = ('code',)

@admin.register(PackageOffer)
class PackageOfferAdmin(admin.ModelAdmin):
    list_display = ('package_bid', 'qr_code', 'is_picked_up', 'is_delivered', 'is_scheduled', 'is_cancelled')
    search_fields = ('package_bid__package__location', 'package_bid__package__destination', 'is_picked_up', 'is_delivered')


@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    list_display = ("user", "balance")
    search_fields = ("user__email",)
    ordering = ("user",)

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ("user", "transaction_type", "amount", "timestamp")
    search_fields = ("user__email", "transaction_type")
    list_filter = ("transaction_type", "timestamp")
    ordering = ("-timestamp",)

@admin.register(Transfer)
class TransferAdmin(admin.ModelAdmin):
    list_display = ("sender", "recipient", "amount", "timestamp")
    search_fields = ("sender__email", "recipient__email")
    ordering = ("-timestamp",)


@admin.register(WithdrawalRequest)
class WithdrawalRequestAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'amount', 'bank_name', 'account_number', 'status', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['user__email', 'bank_name', 'account_number', 'amount', 'status']


@admin.register(Badge)
class BadgeAdmin(admin.ModelAdmin):
    list_display = ('name', 'criteria')
    search_fields = ('name', 'criteria')


@admin.register(UserBadge)
class UserBadgeAdmin(admin.ModelAdmin):
    list_display = ('user', 'badge', 'awarded_at')
    search_fields = ('user__username', 'badge__name')
    list_filter = ('awarded_at',)


@admin.register(ReferralToken)
class ReferralTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'created_at')
    search_fields = ('user__username', 'token')
    readonly_fields = ('token', 'created_at')


@admin.register(Referral)
class ReferralAdmin(admin.ModelAdmin):
    list_display = ('referred_user', 'referred_by', 'token_used', 'created_at')
    search_fields = ('referred_user__username', 'referred_by__username', 'token_used')
    list_filter = ('created_at',)

