"""
Tests for wallet app models, serializers, and views.

This module contains comprehensive tests for wallet-related functionality
including models, serializers, views, and API endpoints.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.authtoken.models import Token

from .models import Wallet, Transaction, Withdrawal, Bank
from .serializers import (
    WalletSerializer, TransactionSerializer, WithdrawalRequestSerializer,
    WithdrawalDetailSerializer, BankSerializer, WalletBalanceSerializer,
    TransactionHistorySerializer
)

User = get_user_model()


class WalletModelTest(TestCase):
    """Test cases for Wallet model."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        self.wallet = Wallet.objects.get(user=self.user)

    def test_wallet_creation(self):
        """Test that wallet is automatically created for new user."""
        self.assertIsNotNone(self.wallet)
        self.assertEqual(self.wallet.user, self.user)
        self.assertEqual(self.wallet.balance, Decimal('0.00'))

    def test_wallet_string_representation(self):
        """Test wallet string representation."""
        expected = f"Wallet of {self.user.email} - ₦0.00"
        self.assertEqual(str(self.wallet), expected)

    def test_add_funds(self):
        """Test adding funds to wallet."""
        initial_balance = self.wallet.balance
        amount = Decimal('100.00')
        
        self.wallet.add_funds(amount)
        self.assertEqual(self.wallet.balance, initial_balance + amount)

    def test_deduct_funds(self):
        """Test deducting funds from wallet."""
        # Add funds first
        self.wallet.add_funds(Decimal('100.00'))
        initial_balance = self.wallet.balance
        amount = Decimal('50.00')
        
        self.wallet.deduct_funds(amount)
        self.assertEqual(self.wallet.balance, initial_balance - amount)

    def test_deduct_funds_insufficient_balance(self):
        """Test deducting funds with insufficient balance."""
        with self.assertRaises(ValueError):
            self.wallet.deduct_funds(Decimal('100.00'))

    def test_has_sufficient_balance(self):
        """Test checking sufficient balance."""
        self.wallet.add_funds(Decimal('100.00'))
        
        self.assertTrue(self.wallet.has_sufficient_balance(Decimal('50.00')))
        self.assertFalse(self.wallet.has_sufficient_balance(Decimal('150.00')))

    def test_get_balance_display(self):
        """Test formatted balance display."""
        self.wallet.add_funds(Decimal('1234.56'))
        expected = "₦1,234.56"
        self.assertEqual(self.wallet.get_balance_display(), expected)


class TransactionModelTest(TestCase):
    """Test cases for Transaction model."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.transaction = Transaction.objects.create(
            user=self.user,
            transaction_type='deposit',
            amount=Decimal('100.00'),
            status='completed',
            reference='TEST123'
        )

    def test_transaction_creation(self):
        """Test transaction creation."""
        self.assertEqual(self.transaction.user, self.user)
        self.assertEqual(self.transaction.transaction_type, 'deposit')
        self.assertEqual(self.transaction.amount, Decimal('100.00'))
        self.assertEqual(self.transaction.status, 'completed')

    def test_transaction_string_representation(self):
        """Test transaction string representation."""
        expected = f"Deposit - ₦100.00 by {self.user.email} (completed)"
        self.assertEqual(str(self.transaction), expected)

    def test_is_successful(self):
        """Test successful transaction check."""
        self.assertTrue(self.transaction.is_successful())
        
        self.transaction.status = 'pending'
        self.assertFalse(self.transaction.is_successful())

    def test_can_be_reversed(self):
        """Test if transaction can be reversed."""
        self.assertTrue(self.transaction.can_be_reversed())
        
        self.transaction.status = 'pending'
        self.assertFalse(self.transaction.can_be_reversed())
        
        self.transaction.transaction_type = 'withdrawal'
        self.assertFalse(self.transaction.can_be_reversed())

    def test_get_amount_display(self):
        """Test formatted amount display."""
        expected = "₦100.00"
        self.assertEqual(self.transaction.get_amount_display(), expected)


class WithdrawalModelTest(TestCase):
    """Test cases for Withdrawal model."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.withdrawal = Withdrawal.objects.create(
            user=self.user,
            bank_name='Test Bank',
            account_number='1234567890',
            amount=Decimal('100.00'),
            status='pending'
        )

    def test_withdrawal_creation(self):
        """Test withdrawal creation."""
        self.assertEqual(self.withdrawal.user, self.user)
        self.assertEqual(self.withdrawal.bank_name, 'Test Bank')
        self.assertEqual(self.withdrawal.amount, Decimal('100.00'))
        self.assertEqual(self.withdrawal.status, 'pending')

    def test_withdrawal_string_representation(self):
        """Test withdrawal string representation."""
        expected = f"Withdrawal by {self.user.email} - ₦100.00 (pending)"
        self.assertEqual(str(self.withdrawal), expected)

    def test_is_processing(self):
        """Test processing status check."""
        self.assertTrue(self.withdrawal.is_processing())
        
        self.withdrawal.status = 'completed'
        self.assertFalse(self.withdrawal.is_processing())

    def test_is_completed(self):
        """Test completed status check."""
        self.assertFalse(self.withdrawal.is_completed())
        
        self.withdrawal.status = 'completed'
        self.assertTrue(self.withdrawal.is_completed())

    def test_is_failed(self):
        """Test failed status check."""
        self.assertFalse(self.withdrawal.is_failed())
        
        self.withdrawal.status = 'failed'
        self.assertTrue(self.withdrawal.is_failed())

    def test_get_amount_display(self):
        """Test formatted amount display."""
        expected = "₦100.00"
        self.assertEqual(self.withdrawal.get_amount_display(), expected)


class BankModelTest(TestCase):
    """Test cases for Bank model."""

    def setUp(self):
        """Set up test data."""
        self.bank = Bank.objects.create(
            name='Test Bank',
            code='TEST',
            slug='test-bank',
            is_active=True
        )

    def test_bank_creation(self):
        """Test bank creation."""
        self.assertEqual(self.bank.name, 'Test Bank')
        self.assertEqual(self.bank.code, 'TEST')
        self.assertEqual(self.bank.is_active, True)

    def test_bank_string_representation(self):
        """Test bank string representation."""
        expected = "Test Bank (TEST)"
        self.assertEqual(str(self.bank), expected)

    def test_get_active_banks(self):
        """Test getting active banks."""
        active_banks = Bank.get_active_banks()
        self.assertIn(self.bank, active_banks)

    def test_get_bank_by_code(self):
        """Test getting bank by code."""
        bank = Bank.get_bank_by_code('TEST')
        self.assertEqual(bank, self.bank)

        # Test non-existent bank
        bank = Bank.get_bank_by_code('NONEXISTENT')
        self.assertIsNone(bank)


class WalletSerializerTest(TestCase):
    """Test cases for WalletSerializer."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.wallet = Wallet.objects.get(user=self.user)

    def test_wallet_serializer_fields(self):
        """Test wallet serializer fields."""
        serializer = WalletSerializer(self.wallet)
        data = serializer.data
        
        self.assertIn('id', data)
        self.assertIn('user', data)
        self.assertIn('balance', data)
        self.assertIn('paystack_customer_code', data)

    def test_wallet_serializer_validation(self):
        """Test wallet serializer validation."""
        data = {'balance': -100}
        serializer = WalletSerializer(data=data)
        self.assertFalse(serializer.is_valid())


class TransactionSerializerTest(TestCase):
    """Test cases for TransactionSerializer."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.transaction = Transaction.objects.create(
            user=self.user,
            transaction_type='deposit',
            amount=Decimal('100.00'),
            status='completed'
        )

    def test_transaction_serializer_fields(self):
        """Test transaction serializer fields."""
        serializer = TransactionSerializer(self.transaction)
        data = serializer.data
        
        self.assertIn('id', data)
        self.assertIn('user', data)
        self.assertIn('amount', data)
        self.assertIn('transaction_type', data)
        self.assertIn('status', data)

    def test_transaction_serializer_validation(self):
        """Test transaction serializer validation."""
        # Test invalid amount
        data = {'amount': -100, 'transaction_type': 'deposit'}
        serializer = TransactionSerializer(data=data)
        self.assertFalse(serializer.is_valid())

        # Test invalid transaction type
        data = {'amount': 100, 'transaction_type': 'invalid'}
        serializer = TransactionSerializer(data=data)
        self.assertFalse(serializer.is_valid())


class WithdrawalRequestSerializerTest(TestCase):
    """Test cases for WithdrawalRequestSerializer."""

    def test_withdrawal_request_serializer_validation(self):
        """Test withdrawal request serializer validation."""
        # Test valid data
        data = {
            'bank_name': 'Test Bank',
            'account_number': '1234567890',
            'amount': Decimal('100.00')
        }
        serializer = WithdrawalRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid())

        # Test invalid bank name
        data = {'bank_name': '', 'account_number': '1234567890', 'amount': 100}
        serializer = WithdrawalRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())

        # Test invalid account number
        data = {'bank_name': 'Test Bank', 'account_number': '123', 'amount': 100}
        serializer = WithdrawalRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())

        # Test invalid amount
        data = {'bank_name': 'Test Bank', 'account_number': '1234567890', 'amount': 50}
        serializer = WithdrawalRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())


class WalletAPITest(APITestCase):
    """Test cases for wallet API endpoints."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def test_get_wallet_balance(self):
        """Test getting wallet balance."""
        url = reverse('get-wallet-balance')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('wallet', response.data)

    def test_get_transaction_history(self):
        """Test getting transaction history."""
        # Create a transaction
        Transaction.objects.create(
            user=self.user,
            transaction_type='deposit',
            amount=Decimal('100.00'),
            status='completed'
        )
        
        url = reverse('get-transaction-history')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('transactions', response.data)
        self.assertIn('pagination', response.data)

    def test_get_withdrawal_history(self):
        """Test getting withdrawal history."""
        # Create a withdrawal
        Withdrawal.objects.create(
            user=self.user,
            bank_name='Test Bank',
            account_number='1234567890',
            amount=Decimal('100.00'),
            status='pending'
        )
        
        url = reverse('get-withdrawal-history')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('withdrawals', response.data)
        self.assertIn('pagination', response.data)

    def test_get_banks_list(self):
        """Test getting banks list."""
        # Create a bank
        Bank.objects.create(
            name='Test Bank',
            code='TEST',
            is_active=True
        )
        
        url = reverse('get-banks-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('banks', response.data)


class WalletViewSetTest(APITestCase):
    """Test cases for WalletViewSet."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def test_wallet_list(self):
        """Test wallet list endpoint."""
        url = reverse('wallet-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)

    def test_wallet_detail(self):
        """Test wallet detail endpoint."""
        wallet = Wallet.objects.get(user=self.user)
        url = reverse('wallet-detail', args=[wallet.id])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['id'], wallet.id)

    def test_my_wallet_action(self):
        """Test my-wallet action."""
        url = reverse('wallet-my-wallet')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('user', response.data)


class TransactionViewSetTest(APITestCase):
    """Test cases for TransactionViewSet."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        # Create a transaction
        self.transaction = Transaction.objects.create(
            user=self.user,
            transaction_type='deposit',
            amount=Decimal('100.00'),
            status='completed'
        )

    def test_transaction_list(self):
        """Test transaction list endpoint."""
        url = reverse('transaction-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)

    def test_transaction_detail(self):
        """Test transaction detail endpoint."""
        url = reverse('transaction-detail', args=[self.transaction.id])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['id'], self.transaction.id)

    def test_transaction_history_action(self):
        """Test transaction history action."""
        url = reverse('transaction-history')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data, list)


class WithdrawalViewSetTest(APITestCase):
    """Test cases for WithdrawalViewSet."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        # Create a bank
        self.bank = Bank.objects.create(
            name='Test Bank',
            code='TEST',
            is_active=True
        )

    def test_withdrawal_create(self):
        """Test withdrawal creation."""
        url = reverse('withdrawal-list')
        data = {
            'bank_name': 'Test Bank',
            'account_number': '1234567890',
            'amount': '100.00'
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('id', response.data)

    def test_withdrawal_list(self):
        """Test withdrawal list endpoint."""
        # Create a withdrawal
        Withdrawal.objects.create(
            user=self.user,
            bank_name='Test Bank',
            account_number='1234567890',
            amount=Decimal('100.00'),
            status='pending'
        )
        
        url = reverse('withdrawal-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)


class BankViewSetTest(APITestCase):
    """Test cases for BankViewSet."""

    def setUp(self):
        """Set up test data."""
        self.bank = Bank.objects.create(
            name='Test Bank',
            code='TEST',
            is_active=True
        )

    def test_bank_list(self):
        """Test bank list endpoint."""
        url = reverse('bank-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)

    def test_bank_detail(self):
        """Test bank detail endpoint."""
        url = reverse('bank-detail', args=[self.bank.id])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['id'], self.bank.id)

    def test_active_banks_action(self):
        """Test active banks action."""
        url = reverse('bank-active')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data, list)
