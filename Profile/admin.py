from django.contrib import admin
from .models import (
    KYC, Vehicle, SubscriptionPlan, Subscription, 
    SocialMediaLink, Badge, UserBadge, ReferralToken, Referral, Notification
)


@admin.register(KYC)
class KYCAdmin(admin.ModelAdmin):
    """
    Admin interface for KYC (Know Your Customer) model.
    
    Provides comprehensive KYC management with verification status tracking.
    """
    list_display = ('user', 'bvn', 'nin', 'verified', 'created_at')
    list_filter = ('verified', 'created_at')
    search_fields = ('user__email', 'bvn', 'nin')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-created_at',)


@admin.register(Vehicle)
class VehicleAdmin(admin.ModelAdmin):
    """
    Admin interface for Vehicle model.
    
    Provides vehicle management with filtering by type and brand.
    """
    list_display = (
        'user', 'vehicle_plate_number', 'vehicle_type', 
        'vehicle_brand', 'vehicle_color'
    )
    list_filter = ('vehicle_type', 'vehicle_brand', 'vehicle_color')
    search_fields = ('user__email', 'vehicle_plate_number', 'vehicle_brand')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    """
    Admin interface for SubscriptionPlan model.
    
    Provides subscription plan management with pricing display.
    """
    list_display = ('name', 'price', 'duration')
    list_filter = ('price', 'duration')
    search_fields = ('name',)
    ordering = ('price',)


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    """
    Admin interface for Subscription model.
    
    Provides subscription tracking with user and plan information.
    """
    list_display = ('user', 'plan', 'start_date', 'end_date')
    list_filter = ('plan', 'start_date', 'end_date')
    search_fields = ('user__email', 'plan__name')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-start_date',)


@admin.register(SocialMediaLink)
class SocialMediaLinkAdmin(admin.ModelAdmin):
    """
    Admin interface for SocialMediaLink model.
    
    Provides social media link management for users.
    """
    list_display = ('user', 'facebook', 'instagram', 'linkedin')
    search_fields = ('user__email', 'facebook', 'instagram', 'linkedin')


@admin.register(Badge)
class BadgeAdmin(admin.ModelAdmin):
    """
    Admin interface for Badge model.
    
    Provides badge management for gamification features.
    """
    list_display = ('name', 'criteria', 'created_at')
    search_fields = ('name', 'criteria')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(UserBadge)
class UserBadgeAdmin(admin.ModelAdmin):
    """
    Admin interface for UserBadge model.
    
    Provides tracking of badges awarded to users.
    """
    list_display = ('user', 'badge', 'awarded_at')
    list_filter = ('awarded_at',)
    search_fields = ('user__email', 'badge__name')
    readonly_fields = ('awarded_at',)


@admin.register(ReferralToken)
class ReferralTokenAdmin(admin.ModelAdmin):
    """
    Admin interface for ReferralToken model.
    
    Provides referral token management for user referrals.
    """
    list_display = ('user', 'token', 'created_at')
    search_fields = ('user__email', 'token')
    readonly_fields = ('token', 'created_at', 'updated_at')
    ordering = ('-created_at',)


@admin.register(Referral)
class ReferralAdmin(admin.ModelAdmin):
    """
    Admin interface for Referral model.
    
    Provides referral tracking with referred user information.
    """
    list_display = ('referred_user', 'referred_by', 'token_used', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('referred_user__email', 'referred_by__email', 'token_used')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-created_at',)


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    """
    Admin interface for Notification model.
    
    Provides comprehensive notification management with filtering,
    searching, bulk actions, and user targeting.
    """
    list_display = ('id', 'user', 'title', 'is_read', 'created_at')
    list_filter = ('is_read', 'created_at')
    search_fields = ('user__email', 'title', 'message')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-created_at',)
    date_hierarchy = 'created_at'
    
    fieldsets = (
        (None, {
            'fields': ('user', 'title', 'message')
        }),
        ('Status', {
            'fields': ('is_read',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    list_per_page = 50
    
    actions = ['mark_as_read', 'mark_as_unread']
    
    @admin.action(description='Mark selected notifications as read')
    def mark_as_read(self, request, queryset):
        queryset.update(is_read=True)
    
    @admin.action(description='Mark selected notifications as unread')
    def mark_as_unread(self, request, queryset):
        queryset.update(is_read=False)