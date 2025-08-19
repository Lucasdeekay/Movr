"""
Wallet app models for financial management.

This module contains models for managing user wallets, transactions,
withdrawals, and bank information with Paystack integration.
"""

from datetime import datetime
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.validators import MinValueValidator, MaxValueValidator

from Api.models import CustomUser as User


class Wallet(models.Model):
    """
    Model representing a user's wallet for managing balances and virtual accounts.
    
    Manages user wallet information including balance, Paystack integration,
    and dedicated virtual account (DVA) details.
    """
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE, 
        related_name="wallet",
        help_text="User account associated with this wallet",
    )
    balance = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=0.00,
        validators=[MinValueValidator(0.00)],
        help_text="Current wallet balance"
    )
    paystack_customer_code = models.CharField(
        max_length=50, 
        unique=True, 
        null=True, 
        blank=True, 
        help_text="Paystack customer code for this user"
    )
    dva_account_number = models.CharField(
        max_length=20, 
        unique=True, 
        null=True, 
        blank=True, 
        help_text="Dedicated Virtual Account number"
    )
    dva_account_name = models.CharField(
        max_length=200, 
        null=True, 
        blank=True, 
        help_text="Name on the DVA account"
    )
    dva_bank_name = models.CharField(
        max_length=100, 
        null=True, 
        blank=True, 
        help_text="Bank name for the DVA"
    )
    dva_assigned_at = models.DateTimeField(
        null=True, 
        blank=True, 
        help_text="When the DVA was assigned"
    )
    updated_at = models.DateTimeField(
        auto_now=True, 
        help_text="When the wallet was last updated"
    )
    created_at = models.DateTimeField(
        auto_now_add=True, 
        help_text="When the wallet was created"
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Wallet"
        verbose_name_plural = "Wallets"
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['balance']),
        ]

    def __str__(self) -> str:
        """String representation of the Wallet."""
        return f"Wallet of {self.user.email} - ₦{self.balance:,.2f}"

    def add_funds(self, amount):
        """
        Add funds to wallet balance.
        
        Args:
            amount: Amount to add (positive decimal)
        """
        if amount <= 0:
            raise ValueError("Amount must be positive.")
        self.balance += amount
        self.save(update_fields=['balance', 'updated_at'])

    def deduct_funds(self, amount):
        """
        Deduct funds from wallet balance.
        
        Args:
            amount: Amount to deduct (positive decimal)
            
        Raises:
            ValueError: If insufficient balance
        """
        if amount <= 0:
            raise ValueError("Amount must be positive.")
        if self.balance < amount:
            raise ValueError("Insufficient balance.")
        self.balance -= amount
        self.save(update_fields=['balance', 'updated_at'])

    def get_balance_display(self):
        """
        Get formatted balance display.
        
        Returns:
            str: Formatted balance with currency symbol
        """
        return f"₦{self.balance:,.2f}"

    def has_sufficient_balance(self, amount):
        """
        Check if wallet has sufficient balance.
        
        Args:
            amount: Amount to check against
            
        Returns:
            bool: True if sufficient balance, False otherwise
        """
        return self.balance >= amount

    @classmethod
    def get_total_balance(cls):
        """
        Get total balance across all wallets.
        
        Returns:
            Decimal: Total balance across all wallets
        """
        return cls.objects.aggregate(total=models.Sum('balance'))['total'] or 0


class Transaction(models.Model):
    """
    Model representing a transaction (deposit, withdrawal, payment) in the wallet.
    
    Manages transaction records including types, amounts, status,
    and Paystack integration details.
    """
    TRANSACTION_TYPES = [
        ('deposit', 'Deposit'),
        ('withdrawal', 'Withdrawal'),
        ('transfer', 'Transfer'),
        ('refund', 'Refund'),
    ]
    TRANSACTION_STATUSES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('reversed', 'Reversed'),
    ]
    
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name="wallet_transactions",
        help_text="User who performed the transaction",
    )
    transaction_type = models.CharField(
        max_length=20, 
        choices=TRANSACTION_TYPES, 
        help_text="Type of transaction"
    )
    reference = models.CharField(
        max_length=50, 
        unique=True, 
        null=True, 
        blank=True, 
        help_text="External reference (e.g., Paystack)"
    )
    amount = models.DecimalField(
        max_digits=12, 
        decimal_places=2,
        validators=[MinValueValidator(0.01)],
        help_text="Transaction amount"
    )
    status = models.CharField(
        max_length=10, 
        choices=TRANSACTION_STATUSES, 
        default='pending', 
        help_text="Transaction status"
    )
    paystack_transaction_id = models.CharField(
        max_length=100,
        null=True, 
        blank=True, 
        help_text="Paystack transaction ID"
    )
    created_at = models.DateTimeField(
        auto_now_add=True, 
        help_text="When the transaction was created"
    )
    updated_at = models.DateTimeField(
        auto_now=True, 
        help_text="When the transaction was last updated"
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Transaction"
        verbose_name_plural = "Transactions"
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['transaction_type', 'status']),
            models.Index(fields=['reference']),
        ]

    def __str__(self) -> str:
        """String representation of the Transaction."""
        return f"{self.get_transaction_type_display()} - ₦{self.amount:,.2f} by {self.user.email} ({self.status})"

    def get_amount_display(self):
        """
        Get formatted amount display.
        
        Returns:
            str: Formatted amount with currency symbol
        """
        return f"₦{self.amount:,.2f}"

    def is_successful(self):
        """
        Check if transaction was successful.
        
        Returns:
            bool: True if transaction is completed, False otherwise
        """
        return self.status == 'completed'

    def can_be_reversed(self):
        """
        Check if transaction can be reversed.
        
        Returns:
            bool: True if transaction can be reversed, False otherwise
        """
        return self.status == 'completed' and self.transaction_type in ['deposit', 'transfer']

    @classmethod
    def get_user_transactions(cls, user, limit=None):
        """
        Get transactions for a specific user.
        
        Args:
            user: User instance
            limit: Maximum number of transactions to return
            
        Returns:
            QuerySet: User's transactions
        """
        queryset = cls.objects.filter(user=user)
        if limit:
            queryset = queryset[:limit]
        return queryset

    @classmethod
    def get_total_by_type(cls, transaction_type):
        """
        Get total amount for a specific transaction type.
        
        Args:
            transaction_type: Type of transaction
            
        Returns:
            Decimal: Total amount for the transaction type
        """
        return cls.objects.filter(
            transaction_type=transaction_type, 
            status='completed'
        ).aggregate(total=models.Sum('amount'))['total'] or 0


class Withdrawal(models.Model):
    """
    Model representing a withdrawal request from a user's wallet.
    
    Manages withdrawal requests including bank details, amounts,
    status tracking, and Paystack transfer integration.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name="withdrawals",
        help_text="User requesting the withdrawal"
    )
    bank_name = models.CharField(
        max_length=100, 
        help_text="Bank name for the withdrawal"
    )
    account_number = models.CharField(
        max_length=20, 
        help_text="Bank account number for the withdrawal"
    )
    account_name = models.CharField(
        max_length=200, 
        null=True, 
        blank=True, 
        help_text="Account name (verified by Paystack)"
    )
    amount = models.DecimalField(
        max_digits=12, 
        decimal_places=2,
        validators=[MinValueValidator(100.00)],
        help_text="Withdrawal amount"
    )
    paystack_recipient_code = models.CharField(
        max_length=50, 
        null=True, 
        blank=True, 
        help_text="Paystack Transfer Recipient Code"
    )
    paystack_transfer_reference = models.CharField(
        max_length=50, 
        unique=True, 
        null=True, 
        blank=True, 
        help_text="Unique reference for Paystack transfer"
    )
    paystack_transfer_id = models.CharField(
        max_length=100,
        null=True, 
        blank=True, 
        help_text="Paystack internal Transfer ID"
    )
    status = models.CharField(
        max_length=10, 
        choices=STATUS_CHOICES, 
        default='pending', 
        help_text="Withdrawal status"
    )
    failure_reason = models.TextField(
        null=True, 
        blank=True, 
        help_text="Reason for failure (if any)"
    )
    created_at = models.DateTimeField(
        auto_now_add=True, 
        help_text="When the withdrawal was created"
    )
    updated_at = models.DateTimeField(
        auto_now=True, 
        help_text="When the withdrawal was last updated"
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Withdrawal"
        verbose_name_plural = "Withdrawals"
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['bank_name']),
        ]

    def __str__(self) -> str:
        """String representation of the Withdrawal."""
        return f"Withdrawal by {self.user.email} - ₦{self.amount:,.2f} ({self.status})"

    def get_amount_display(self):
        """
        Get formatted amount display.
        
        Returns:
            str: Formatted amount with currency symbol
        """
        return f"₦{self.amount:,.2f}"

    def is_processing(self):
        """
        Check if withdrawal is being processed.
        
        Returns:
            bool: True if withdrawal is processing, False otherwise
        """
        return self.status in ['pending', 'processing']

    def is_completed(self):
        """
        Check if withdrawal is completed.
        
        Returns:
            bool: True if withdrawal is completed, False otherwise
        """
        return self.status == 'completed'

    def is_failed(self):
        """
        Check if withdrawal failed.
        
        Returns:
            bool: True if withdrawal failed, False otherwise
        """
        return self.status == 'failed'

    @classmethod
    def get_pending_withdrawals(cls):
        """
        Get all pending withdrawals.
        
        Returns:
            QuerySet: Pending withdrawals
        """
        return cls.objects.filter(status='pending')

    @classmethod
    def get_user_withdrawals(cls, user, limit=None):
        """
        Get withdrawals for a specific user.
        
        Args:
            user: User instance
            limit: Maximum number of withdrawals to return
            
        Returns:
            QuerySet: User's withdrawals
        """
        queryset = cls.objects.filter(user=user)
        if limit:
            queryset = queryset[:limit]
        return queryset


class Bank(models.Model):
    """
    Model representing a bank supported for wallet withdrawals.
    
    Manages bank information for withdrawal operations
    including bank codes and Paystack integration.
    """
    name = models.CharField(
        max_length=100, 
        unique=True, 
        help_text="Bank name"
    )
    code = models.CharField(
        max_length=10, 
        unique=True, 
        help_text="Bank code (e.g., NUBAN code)"
    )
    slug = models.CharField(
        max_length=100, 
        unique=True, 
        null=True, 
        blank=True, 
        help_text="Paystack slug for the bank"
    )
    is_active = models.BooleanField(
        default=True, 
        help_text="Whether the bank is currently active/available"
    )
    added_at = models.DateTimeField(
        auto_now_add=True, 
        help_text="When the bank was added"
    )
    updated_at = models.DateTimeField(
        auto_now=True, 
        help_text="When the bank was last updated"
    )

    class Meta:
        ordering = ['name']
        verbose_name = "Bank"
        verbose_name_plural = "Banks"
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['code']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self) -> str:
        """String representation of the Bank."""
        return f"{self.name} ({self.code})"

    @classmethod
    def get_active_banks(cls):
        """
        Get all active banks.
        
        Returns:
            QuerySet: Active banks
        """
        return cls.objects.filter(is_active=True)

    @classmethod
    def get_bank_by_code(cls, code):
        """
        Get bank by code.
        
        Args:
            code: Bank code
            
        Returns:
            Bank: Bank instance or None
        """
        try:
            return cls.objects.get(code=code, is_active=True)
        except cls.DoesNotExist:
            return None


