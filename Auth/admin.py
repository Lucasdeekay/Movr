from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser, OTP


@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    """
    Admin interface for CustomUser model.
    
    Provides comprehensive user management with filtering,
    searching, and user status tracking.
    """
    list_display = (
        'email', 'first_name', 'last_name', 'phone_number',
        'is_email_verified', 'two_factor_enabled', 'is_staff', 'date_joined'
    )
    list_filter = (
        'is_email_verified', 'two_factor_enabled', 'is_staff',
        'is_superuser', 'date_joined'
    )
    search_fields = ('email', 'first_name', 'last_name', 'phone_number')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'phone_number', 'profile_picture')}),
        ('Verification', {'fields': ('is_email_verified', 'two_factor_enabled')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important Dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'password1', 'password2'),
        }),
    )


@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    """
    Admin interface for OTP model.
    
    Provides OTP tracking with filtering by usage status
    and expiration.
    """
    list_display = ('user', 'code', 'is_used', 'created_at', 'expires_at')
    search_fields = ('user__email', 'code')
    list_filter = ('is_used', 'created_at', 'expires_at')
    readonly_fields = ('code', 'created_at', 'expires_at')
    ordering = ('-created_at',)
    
    def has_view_permission(self, request, obj=None):
        return True
    
    def has_change_permission(self, request, obj=None):
        return False