"""
Django Admin configuration for wallet app models.

This module contains admin configurations for wallet-related models
including wallets, transactions, withdrawals, and banks with
comprehensive management capabilities.
"""

from django.contrib import admin
from django.utils.html import format_html
from django.db.models import Sum, Count, Avg
from django.utils import timezone

from .models import Wallet, Transaction, Withdrawal, Bank


@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    """
    Admin configuration for Wallet model.
    
    Provides comprehensive wallet management including balance tracking,
    user information, and Paystack integration details.
    """
    list_display = [
        'get_user_email', 'get_balance_display', 'get_paystack_customer_code',
        'get_dva_info', 'created_at', 'updated_at'
    ]
    list_filter = [
        'created_at', 'updated_at', 'dva_assigned_at'
    ]
    search_fields = [
        'user__email', 'user__first_name', 'user__last_name',
        'paystack_customer_code', 'dva_account_number'
    ]
    readonly_fields = [
        'user', 'paystack_customer_code', 'dva_account_number',
        'dva_account_name', 'dva_bank_name', 'dva_assigned_at',
        'created_at', 'updated_at'
    ]
    ordering = ['-created_at']
    list_per_page = 25

    fieldsets = (
        ('User Information', {
            'fields': ('user',)
        }),
        ('Balance Information', {
            'fields': ('balance',)
        }),
        ('Paystack Integration', {
            'fields': ('paystack_customer_code',),
            'classes': ('collapse',)
        }),
        ('Dedicated Virtual Account', {
            'fields': ('dva_account_number', 'dva_account_name', 'dva_bank_name', 'dva_assigned_at'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_user_email(self, obj):
        """Get user email for display."""
        return obj.user.email if obj.user else 'N/A'
    get_user_email.short_description = 'User Email'
    get_user_email.admin_order_field = 'user__email'

    def get_balance_display(self, obj):
        """Get formatted balance display."""
        return f"₦{obj.balance:,.2f}"
    get_balance_display.short_description = 'Balance'
    get_balance_display.admin_order_field = 'balance'

    def get_paystack_customer_code(self, obj):
        """Get Paystack customer code with formatting."""
        if obj.paystack_customer_code:
            return format_html('<span style="color: green;">✓</span> {}', obj.paystack_customer_code)
        return format_html('<span style="color: red;">✗</span> Not assigned')
    get_paystack_customer_code.short_description = 'Paystack Customer'

    def get_dva_info(self, obj):
        """Get DVA information with formatting."""
        if obj.dva_account_number:
            return format_html(
                '<span style="color: green;">✓</span> {}<br><small>{}</small>',
                obj.dva_account_number,
                obj.dva_bank_name or 'Unknown Bank'
            )
        return format_html('<span style="color: red;">✗</span> Not assigned')
    get_dva_info.short_description = 'DVA Account'

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user')

    def has_add_permission(self, request):
        """Disable manual wallet creation."""
        return False

    def has_change_permission(self, request, obj=None):
        """Allow editing balance only."""
        return True

    def has_delete_permission(self, request, obj=None):
        """Disable wallet deletion."""
        return False


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    """
    Admin configuration for Transaction model.
    
    Provides comprehensive transaction management including
    transaction types, amounts, status tracking, and Paystack integration.
    """
    list_display = [
        'get_user_email', 'get_transaction_type_display', 'get_amount_display',
        'get_status_display', 'get_reference_display', 'created_at'
    ]
    list_filter = [
        'transaction_type', 'status', 'created_at', 'updated_at'
    ]
    search_fields = [
        'user__email', 'user__first_name', 'user__last_name',
        'reference', 'paystack_transaction_id'
    ]
    readonly_fields = [
        'user', 'reference', 'paystack_transaction_id',
        'created_at', 'updated_at'
    ]
    ordering = ['-created_at']
    list_per_page = 25

    fieldsets = (
        ('User Information', {
            'fields': ('user',)
        }),
        ('Transaction Details', {
            'fields': ('transaction_type', 'amount', 'status')
        }),
        ('Reference Information', {
            'fields': ('reference', 'paystack_transaction_id'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_user_email(self, obj):
        """Get user email for display."""
        return obj.user.email if obj.user else 'N/A'
    get_user_email.short_description = 'User Email'
    get_user_email.admin_order_field = 'user__email'

    def get_transaction_type_display(self, obj):
        """Get formatted transaction type display."""
        type_colors = {
            'deposit': 'green',
            'withdrawal': 'red',
            'transfer': 'blue',
            'refund': 'orange'
        }
        color = type_colors.get(obj.transaction_type, 'black')
        return format_html(
            '<span style="color: {};">{}</span>',
            color,
            obj.get_transaction_type_display()
        )
    get_transaction_type_display.short_description = 'Type'
    get_transaction_type_display.admin_order_field = 'transaction_type'

    def get_amount_display(self, obj):
        """Get formatted amount display."""
        return f"₦{obj.amount:,.2f}"
    get_amount_display.short_description = 'Amount'
    get_amount_display.admin_order_field = 'amount'

    def get_status_display(self, obj):
        """Get formatted status display."""
        status_colors = {
            'pending': 'orange',
            'completed': 'green',
            'failed': 'red',
            'reversed': 'purple'
        }
        color = status_colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {};">{}</span>',
            color,
            obj.get_status_display()
        )
    get_status_display.short_description = 'Status'
    get_status_display.admin_order_field = 'status'

    def get_reference_display(self, obj):
        """Get reference with formatting."""
        if obj.reference:
            return format_html('<code>{}</code>', obj.reference)
        return 'N/A'
    get_reference_display.short_description = 'Reference'

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user')

    def has_add_permission(self, request):
        """Disable manual transaction creation."""
        return False

    def has_change_permission(self, request, obj=None):
        """Allow editing status only."""
        return True

    def has_delete_permission(self, request, obj=None):
        """Disable transaction deletion."""
        return False


@admin.register(Withdrawal)
class WithdrawalAdmin(admin.ModelAdmin):
    """
    Admin configuration for Withdrawal model.
    
    Provides comprehensive withdrawal management including
    bank details, amounts, status tracking, and Paystack integration.
    """
    list_display = [
        'get_user_email', 'get_bank_display', 'get_amount_display',
        'get_status_display', 'get_reference_display', 'created_at'
    ]
    list_filter = [
        'status', 'bank_name', 'created_at', 'updated_at'
    ]
    search_fields = [
        'user__email', 'user__first_name', 'user__last_name',
        'bank_name', 'account_number', 'paystack_transfer_reference'
    ]
    readonly_fields = [
        'user', 'paystack_recipient_code', 'paystack_transfer_reference',
        'paystack_transfer_id', 'created_at', 'updated_at'
    ]
    ordering = ['-created_at']
    list_per_page = 25

    fieldsets = (
        ('User Information', {
            'fields': ('user',)
        }),
        ('Bank Details', {
            'fields': ('bank_name', 'account_number', 'account_name')
        }),
        ('Withdrawal Details', {
            'fields': ('amount', 'status', 'failure_reason')
        }),
        ('Paystack Integration', {
            'fields': ('paystack_recipient_code', 'paystack_transfer_reference', 'paystack_transfer_id'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    actions = ['approve_withdrawals', 'reject_withdrawals', 'mark_as_processing']

    def get_user_email(self, obj):
        """Get user email for display."""
        return obj.user.email if obj.user else 'N/A'
    get_user_email.short_description = 'User Email'
    get_user_email.admin_order_field = 'user__email'

    def get_bank_display(self, obj):
        """Get bank information with formatting."""
        return format_html(
            '{}<br><small>{}</small>',
            obj.bank_name,
            obj.account_number
        )
    get_bank_display.short_description = 'Bank Details'

    def get_amount_display(self, obj):
        """Get formatted amount display."""
        return f"₦{obj.amount:,.2f}"
    get_amount_display.short_description = 'Amount'
    get_amount_display.admin_order_field = 'amount'

    def get_status_display(self, obj):
        """Get formatted status display."""
        status_colors = {
            'pending': 'orange',
            'processing': 'blue',
            'completed': 'green',
            'failed': 'red',
            'cancelled': 'gray'
        }
        color = status_colors.get(obj.status, 'black')
        return format_html(
            '<span style="color: {};">{}</span>',
            color,
            obj.get_status_display()
        )
    get_status_display.short_description = 'Status'
    get_status_display.admin_order_field = 'status'

    def get_reference_display(self, obj):
        """Get reference with formatting."""
        if obj.paystack_transfer_reference:
            return format_html('<code>{}</code>', obj.paystack_transfer_reference)
        return 'N/A'
    get_reference_display.short_description = 'Reference'

    def approve_withdrawals(self, request, queryset):
        """Approve selected withdrawals."""
        updated = queryset.filter(status='pending').update(status='processing')
        self.message_user(request, f'{updated} withdrawals marked as processing.')
    approve_withdrawals.short_description = 'Approve selected withdrawals'

    def reject_withdrawals(self, request, queryset):
        """Reject selected withdrawals."""
        updated = queryset.filter(status='pending').update(status='failed')
        self.message_user(request, f'{updated} withdrawals marked as failed.')
    reject_withdrawals.short_description = 'Reject selected withdrawals'

    def mark_as_processing(self, request, queryset):
        """Mark selected withdrawals as processing."""
        updated = queryset.filter(status='pending').update(status='processing')
        self.message_user(request, f'{updated} withdrawals marked as processing.')
    mark_as_processing.short_description = 'Mark as processing'

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user')

    def has_add_permission(self, request):
        """Disable manual withdrawal creation."""
        return False

    def has_change_permission(self, request, obj=None):
        """Allow editing status and failure reason."""
        return True

    def has_delete_permission(self, request, obj=None):
        """Disable withdrawal deletion."""
        return False


@admin.register(Bank)
class BankAdmin(admin.ModelAdmin):
    """
    Admin configuration for Bank model.
    
    Provides comprehensive bank management including
    bank codes, Paystack integration, and active status.
    """
    list_display = [
        'name', 'code', 'slug', 'is_active', 'added_at'
    ]
    list_filter = [
        'is_active', 'added_at', 'updated_at'
    ]
    search_fields = [
        'name', 'code', 'slug'
    ]
    readonly_fields = [
        'added_at', 'updated_at'
    ]
    ordering = ['name']
    list_per_page = 25

    fieldsets = (
        ('Bank Information', {
            'fields': ('name', 'code', 'slug')
        }),
        ('Status', {
            'fields': ('is_active',)
        }),
        ('Timestamps', {
            'fields': ('added_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    actions = ['activate_banks', 'deactivate_banks']

    def activate_banks(self, request, queryset):
        """Activate selected banks."""
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} banks activated.')
    activate_banks.short_description = 'Activate selected banks'

    def deactivate_banks(self, request, queryset):
        """Deactivate selected banks."""
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} banks deactivated.')
    deactivate_banks.short_description = 'Deactivate selected banks'

    def has_delete_permission(self, request, obj=None):
        """Disable bank deletion."""
        return False