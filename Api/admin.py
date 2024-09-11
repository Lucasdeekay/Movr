from django.contrib import admin
from .models import CustomUser, KYC, Vehicle, PaymentMethod, SubscriptionPlan, Subscription, OTP, SocialMediaLink


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




# from django.contrib import admin
# from .models import (
#     User, UserProfile, PaymentMethod, SubscriptionPlan, Subscription,
#     TravelPlan, RideMatch, RideTracking, Insurance, DamageReport,
#     KYC, HomeAwayStatus, SOSAlert, SocialLink, Badge, UserBadge, Review
# )
#
# # User and Profile Admin
# @admin.register(User)
# class UserAdmin(admin.ModelAdmin):
#     list_display = ('username', 'email', 'phone_number', 'is_email_verified', 'is_phone_verified', 'two_factor_enabled')
#     search_fields = ('username', 'email', 'phone_number')
#     list_filter = ('is_email_verified', 'is_phone_verified', 'two_factor_enabled', 'is_staff')
#
# @admin.register(UserProfile)
# class UserProfileAdmin(admin.ModelAdmin):
#     list_display = ('user', 'country', 'city', 'created_at')
#     search_fields = ('user__username', 'country', 'city')
#     list_filter = ('country', 'created_at')
#
# # Payment Admin
# @admin.register(PaymentMethod)
# class PaymentMethodAdmin(admin.ModelAdmin):
#     list_display = ('user', 'method_name')
#     search_fields = ('user__username', 'method_name')
#     list_filter = ('method_name',)
#
# @admin.register(SubscriptionPlan)
# class SubscriptionPlanAdmin(admin.ModelAdmin):
#     list_display = ('name', 'price', 'duration')
#     search_fields = ('name',)
#     list_filter = ('price', 'duration')
#
# @admin.register(Subscription)
# class SubscriptionAdmin(admin.ModelAdmin):
#     list_display = ('user', 'plan', 'start_date', 'end_date')
#     search_fields = ('user__username', 'plan__name')
#     list_filter = ('start_date', 'end_date')
#
# # Travel and Ride Admin
# @admin.register(TravelPlan)
# class TravelPlanAdmin(admin.ModelAdmin):
#     list_display = ('user', 'route', 'departure_time', 'vehicle_type', 'package_delivery', 'insurance_coverage')
#     search_fields = ('user__username', 'route', 'vehicle_type')
#     list_filter = ('departure_time', 'vehicle_type', 'package_delivery', 'insurance_coverage')
#
# @admin.register(RideMatch)
# class RideMatchAdmin(admin.ModelAdmin):
#     list_display = ('travel_plan', 'matched_user', 'status')
#     search_fields = ('travel_plan__route', 'matched_user__username', 'status')
#     list_filter = ('status',)
#
# @admin.register(RideTracking)
# class RideTrackingAdmin(admin.ModelAdmin):
#     list_display = ('ride_match', 'current_location', 'updated_at')
#     search_fields = ('ride_match__travel_plan__route', 'current_location')
#     list_filter = ('updated_at',)
#
# # Delivery and Insurance Admin
# @admin.register(Insurance)
# class InsuranceAdmin(admin.ModelAdmin):
#     list_display = ('travel_plan', 'insurance_company', 'coverage_amount', 'fee')
#     search_fields = ('travel_plan__user__username', 'insurance_company')
#     list_filter = ('coverage_amount', 'fee')
#
# @admin.register(DamageReport)
# class DamageReportAdmin(admin.ModelAdmin):
#     list_display = ('travel_plan', 'description', 'reported_at')
#     search_fields = ('travel_plan__user__username',)
#     list_filter = ('reported_at',)
#
# # Safety Admin
# @admin.register(KYC)
# class KYCAdmin(admin.ModelAdmin):
#     list_display = ('user', 'bvn', 'nin', 'verified')
#     search_fields = ('user__username', 'bvn', 'nin')
#     list_filter = ('verified',)
#
# @admin.register(HomeAwayStatus)
# class HomeAwayStatusAdmin(admin.ModelAdmin):
#     list_display = ('user', 'is_home', 'location')
#     search_fields = ('user__username', 'location')
#     list_filter = ('is_home',)
#
# @admin.register(SOSAlert)
# class SOSAlertAdmin(admin.ModelAdmin):
#     list_display = ('user', 'ride', 'message', 'sent_at', 'coordinates')
#     search_fields = ('user__username', 'ride__travel_plan__route', 'message')
#     list_filter = ('sent_at',)
#
#
# @admin.register(Badge)
# class BadgeAdmin(admin.ModelAdmin):
#     list_display = ('name', 'description', 'criteria')
#     search_fields = ('name', 'criteria')
#
# @admin.register(UserBadge)
# class UserBadgeAdmin(admin.ModelAdmin):
#     list_display = ('user', 'badge', 'awarded_at')
#     search_fields = ('user__username', 'badge__name')
#     list_filter = ('awarded_at',)
#
# @admin.register(Review)
# class ReviewAdmin(admin.ModelAdmin):
#     list_display = ('ride_match', 'reviewer', 'rating', 'created_at')
#     search_fields = ('ride_match__travel_plan__route', 'reviewer__username', 'rating')
#     list_filter = ('rating', 'created_at')
