"""
Serializers for wallet app models.

This module contains serializers for handling data validation and transformation
for wallet-related models including wallets, transactions, withdrawals, and banks.
"""

from rest_framework import serializers
from django.core.validators import MinValueValidator, MaxValueValidator

from .models import Wallet, Transaction, Withdrawal, Bank
from auth_app.models import User

import logging

logger = logging.getLogger(__name__)


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model in wallet context.
    
    Provides user information for nested serialization in wallet operations.
    """
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name']


class WalletSerializer(serializers.ModelSerializer):
    """
    Serializer for Wallet model.
    
    Handles wallet data serialization and deserialization including
    balance, Paystack integration, and DVA account information.
    """
    user = UserSerializer(read_only=True)

    class Meta:
        model = Wallet
        fields = (
            'id', 'user', 'balance',
            'dva_account_number', 'dva_account_name', 'dva_bank_name',
            'dva_assigned_at', 'updated_at', 'created_at'
        )
        read_only_fields = (
            'id', 'user', 'balance',
            'dva_account_number', 'dva_account_name', 'dva_bank_name',
            'dva_assigned_at', 'updated_at', 'created_at'
        )

    def validate_balance(self, value):
        """
        Validate wallet balance.
        
        Ensures balance is not negative.
        """
        if value < 0:
            raise serializers.ValidationError("Wallet balance cannot be negative.")
        return value


class TransactionSerializer(serializers.ModelSerializer):
    """
    Serializer for Transaction model.
    
    Handles transaction data serialization and deserialization including
    transaction types, amounts, and Paystack integration.
    """
    user = UserSerializer(read_only=True)

    class Meta:
        model = Transaction
        fields = (
            'id', 'user', 'amount', 'transaction_type', 'reference',
            'status', 'created_at', 'updated_at'
        )
        read_only_fields = (
            'id', 'user', 'status', 'reference',
            'created_at', 'updated_at'
        )
        extra_kwargs = {
            'amount': {'required': True},
            'transaction_type': {'required': True}
        }

    def validate_amount(self, value):
        """
        Validate transaction amount.
        
        Ensures amount is positive and within reasonable limits.
        """
        if value <= 0:
            raise serializers.ValidationError("Transaction amount must be positive.")
        
        if value > 1000000:  # 1 million limit
            raise serializers.ValidationError("Transaction amount is too high.")
        
        return value

    def validate_transaction_type(self, value):
        """
        Validate transaction type.
        
        Ensures transaction type is valid.
        """
        valid_types = ['deposit', 'withdrawal', 'transfer', 'refund']
        if value not in valid_types:
            raise serializers.ValidationError(f"Invalid transaction type. Must be one of: {valid_types}")
        return value


class WithdrawalRequestSerializer(serializers.ModelSerializer):
    """
    Serializer for withdrawal requests.
    
    Handles withdrawal request data validation and processing
    including bank details and amount validation.
    """
    bank_name = serializers.CharField(max_length=100)
    account_number = serializers.CharField(max_length=20)
    amount = serializers.DecimalField(
        max_digits=12, 
        decimal_places=2,
        validators=[MinValueValidator(100.00)]  # Minimum withdrawal amount
    )

    class Meta:
        model = Withdrawal
        fields = ['bank_name', 'account_number', 'amount']

    def validate_bank_name(self, value):
        """
        Validate bank name.
        
        Ensures bank name is not empty and has reasonable length.
        """
        if not value or not value.strip():
            raise serializers.ValidationError("Bank name cannot be empty.")
        
        if len(value) > 100:
            raise serializers.ValidationError("Bank name is too long.")
        
        return value.strip()

    def validate_account_number(self, value):
        """
        Validate account number.
        
        Ensures account number is numeric and has correct length.
        """
        if not value or not value.strip():
            raise serializers.ValidationError("Account number cannot be empty.")
        
        if not value.isdigit():
            raise serializers.ValidationError("Account number must contain only digits.")
        
        if len(value) < 10 or len(value) > 10:
            raise serializers.ValidationError("Account number must be exactly 10 digits.")
        
        return value.strip()

    def validate_amount(self, value):
        """
        Validate withdrawal amount.
        
        Ensures amount is positive and within withdrawal limits.
        """
        if value <= 0:
            raise serializers.ValidationError("Withdrawal amount must be positive.")
        
        if value > 100000:  # Maximum withdrawal limit
            raise serializers.ValidationError("Withdrawal amount exceeds maximum limit.")
        
        return value

    def validate(self, data):
        """
        Validate withdrawal request data.
        
        Performs cross-field validation for withdrawal requests.
        """
        # Additional validation can be added here
        # For example, checking user balance, withdrawal limits, etc.
        return data


class WithdrawalDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for withdrawal details.
    
    Provides comprehensive withdrawal information including
    user details, bank information, and Paystack integration.
    """
    user = UserSerializer(read_only=True)

    class Meta:
        model = Withdrawal
        fields = [
            'id', 'user', 'bank_name', 'account_number', 'account_name',
            'amount', 'status',
            'transfer_reference',
            'failure_reason', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user', 'bank_name', 'account_number', 'account_name',
            'amount', 'status',
            'transfer_reference',
            'failure_reason', 'created_at', 'updated_at'
        ]

    def get_status_display(self, obj):
        """
        Get human-readable status.
        
        Returns a user-friendly status description.
        """
        status_map = {
            'pending': 'Pending',
            'processing': 'Processing',
            'completed': 'Completed',
            'failed': 'Failed',
            'cancelled': 'Cancelled'
        }
        return status_map.get(obj.status, obj.status)


class BankSerializer(serializers.ModelSerializer):
    """
    Serializer for Bank model.
    
    Handles bank data serialization for bank listing and selection.
    """
    class Meta:
        model = Bank
        fields = ['id', 'name', 'code', 'slug']
        read_only_fields = ['id', 'name', 'code', 'slug']

    def validate_name(self, value):
        """
        Validate bank name.
        
        Ensures bank name is not empty and has reasonable length.
        """
        if not value or not value.strip():
            raise serializers.ValidationError("Bank name cannot be empty.")
        
        if len(value) > 100:
            raise serializers.ValidationError("Bank name is too long.")
        
        return value.strip()

    def validate_code(self, value):
        """
        Validate bank code.
        
        Ensures bank code is not empty and has correct format.
        """
        if not value or not value.strip():
            raise serializers.ValidationError("Bank code cannot be empty.")
        
        if len(value) > 10:
            raise serializers.ValidationError("Bank code is too long.")
        
        return value.strip()


class WalletBalanceSerializer(serializers.Serializer):
    """
    Serializer for wallet balance operations.
    
    Handles balance updates and balance queries.
    """
    balance = serializers.DecimalField(
        max_digits=12, 
        decimal_places=2,
        read_only=True
    )
    currency = serializers.CharField(default='NGN', read_only=True)
    last_updated = serializers.DateTimeField(read_only=True)

    def to_representation(self, instance):
        """
        Custom representation for wallet balance.
        
        Returns formatted balance information.
        """
        return {
            'balance': str(instance.balance),
            'currency': 'NGN',
            'last_updated': instance.updated_at.isoformat() if instance.updated_at else None
        }


class TransactionHistorySerializer(serializers.ModelSerializer):
    """
    Serializer for transaction history.
    
    Provides transaction history with additional metadata
    for display and analysis.
    """
    user = UserSerializer(read_only=True)
    transaction_type_display = serializers.SerializerMethodField()
    formatted_amount = serializers.SerializerMethodField()

    class Meta:
        model = Transaction
        fields = (
            'id', 'user', 'amount', 'transaction_type', 'transaction_type_display',
            'formatted_amount', 'reference', 'status', 'created_at'
        )
        read_only_fields = (
            'id', 'user', 'amount', 'transaction_type', 'reference',
            'status', 'created_at'
        )

    def get_transaction_type_display(self, obj):
        """
        Get human-readable transaction type.
        
        Returns a user-friendly transaction type description.
        """
        type_map = {
            'deposit': 'Deposit',
            'withdrawal': 'Withdrawal',
            'transfer': 'Transfer',
            'refund': 'Refund'
        }
        return type_map.get(obj.transaction_type, obj.transaction_type)

    def get_formatted_amount(self, obj):
        """
        Get formatted amount with currency.
        
        Returns amount formatted with Nigerian Naira symbol.
        """
        return f"₦{obj.amount:,.2f}"

