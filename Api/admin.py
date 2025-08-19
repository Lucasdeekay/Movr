from django.contrib import admin, messages
from django.utils.html import format_html
from django.db.models import Count
from .models import CustomUser, KYC, Notification, Vehicle, SubscriptionPlan, Subscription, OTP, SocialMediaLink, \
    Route, ScheduledRoute, Day, Package, Bid, QRCode, PackageOffer, \
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

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    """
    Admin interface for Notification model.
    
    Provides comprehensive notification management with filtering,
    searching, bulk actions, and user targeting.
    """
    list_display = (
        'user', 'get_title_display', 'get_message_preview', 
        'created_at', 'is_read_display', 'get_user_email'
    )
    list_filter = ('is_read', 'created_at')
    search_fields = ('user__email', 'user__first_name', 'user__last_name', 'title', 'message')
    ordering = ('-created_at',)
    readonly_fields = ('created_at',)
    list_per_page = 25
    
    fieldsets = (
        ('Notification Information', {
            'fields': ('user', 'title', 'message')
        }),
        ('Status', {
            'fields': ('is_read',)
        }),
        ('Timestamps', {
            'fields': ('created_at',)
        }),
    )
    
    actions = ['mark_as_read', 'mark_as_unread', 'send_notification_to_all']

    def get_title_display(self, obj):
        """Display title or 'No Title' if empty."""
        return obj.title or "No Title"
    get_title_display.short_description = 'Title'
    get_title_display.admin_order_field = 'title'

    def get_message_preview(self, obj):
        """Display message preview (first 50 characters)."""
        preview = obj.message[:50] + "..." if len(obj.message) > 50 else obj.message
        return preview
    get_message_preview.short_description = 'Message Preview'

    def is_read_display(self, obj):
        """Display read status with color coding."""
        if obj.is_read:
            return format_html('<span style="color: green;">✓ Read</span>')
        return format_html('<span style="color: red;">✗ Unread</span>')
    is_read_display.short_description = 'Status'
    is_read_display.admin_order_field = 'is_read'

    def get_user_email(self, obj):
        """Get user email for display."""
        return obj.user.email
    get_user_email.short_description = 'User Email'
    get_user_email.admin_order_field = 'user__email'

    def mark_as_read(self, request, queryset):
        """Mark selected notifications as read."""
        updated = queryset.update(is_read=True)
        self.message_user(
            request, 
            f"Successfully marked {updated} notification(s) as read.",
            level=messages.SUCCESS
        )
    mark_as_read.short_description = "Mark selected notifications as read"

    def mark_as_unread(self, request, queryset):
        """Mark selected notifications as unread."""
        updated = queryset.update(is_read=False)
        self.message_user(
            request, 
            f"Successfully marked {updated} notification(s) as unread.",
            level=messages.SUCCESS
        )
    mark_as_unread.short_description = "Mark selected notifications as unread"

    def send_notification_to_all(self, request, queryset):
        """Send selected notification to all users."""
        if queryset.count() != 1:
            self.message_user(
                request, 
                "Please select only one notification to send.", 
                level=messages.ERROR
            )
            return
        
        notification = queryset.first()
        users = CustomUser.objects.filter(is_active=True)
        
        # Create notifications in batches to avoid memory issues
        batch_size = 1000
        notifications = []
        
        for user in users:
            notifications.append(Notification(
                user=user, 
                title=notification.title, 
                message=notification.message
            ))
            
            if len(notifications) >= batch_size:
                Notification.objects.bulk_create(notifications)
                notifications = []
        
        # Create remaining notifications
        if notifications:
            Notification.objects.bulk_create(notifications)

        self.message_user(
            request, 
            f"Notification sent to {users.count()} users!", 
            level=messages.SUCCESS
        )
    send_notification_to_all.short_description = "Send selected notification to all users"

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user')

    def get_readonly_fields(self, request, obj=None):
        """Make created_at readonly for all users."""
        return self.readonly_fields + ('created_at',)

    def has_add_permission(self, request):
        """Allow adding notifications."""
        return True

    def has_change_permission(self, request, obj=None):
        """Allow changing notifications."""
        return True

    def has_delete_permission(self, request, obj=None):
        """Allow deleting notifications."""
        return True