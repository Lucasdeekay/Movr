"""
ViewSets for wallet app models.

This module contains ViewSets for handling CRUD operations on wallet-related models
including wallets, transactions, withdrawals, and banks with proper filtering and pagination.
"""

from rest_framework import viewsets, status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework.decorators import action
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from django.db import transaction as db_transaction

from .models import Wallet, Transaction, Withdrawal, Bank
from .serializers import (
    WalletSerializer,
    TransactionSerializer,
    WithdrawalRequestSerializer,
    WithdrawalDetailSerializer,
    BankSerializer,
    WalletBalanceSerializer,
    TransactionHistorySerializer,
)

import logging

logger = logging.getLogger(__name__)


class CustomPagination(PageNumberPagination):
    """
    Custom pagination class for consistent page sizing across the API.
    """
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100


class WalletViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for Wallet model.
    
    Provides read-only operations for wallets with user-specific filtering.
    Wallet creation and updates (balance) are handled internally.
    """
    serializer_class = WalletSerializer
    pagination_class = CustomPagination
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter)
    filterset_fields = ['balance', 'created_at']
    search_fields = ['user__email', 'user__first_name', 'user__last_name']
    ordering_fields = ['balance', 'created_at', 'updated_at']
    ordering = ['-created_at']
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Return wallet for the authenticated user only."""
        return Wallet.objects.filter(user=self.request.user)

    @action(detail=False, methods=['get'], url_path='balance')
    def get_balance(self, request):
        """
        Get wallet balance for the authenticated user.
        
        Returns current balance and currency information.
        """
        try:
            wallet = Wallet.objects.get(user=request.user)
            serializer = WalletBalanceSerializer(wallet)
            logger.info(f"Balance retrieved for user: {request.user.email}")
            return Response(serializer.data)
        except Wallet.DoesNotExist:
            logger.warning(f"Wallet not found for user: {request.user.email}")
            return Response(
                {"message": "Wallet not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error retrieving balance for user {request.user.email}: {str(e)}")
            return Response(
                {"message": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class TransactionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for Transaction model.
    
    Provides read-only operations for transactions with user-specific filtering.
    Transaction creation is handled by webhook or internal logic.
    """
    serializer_class = TransactionSerializer
    pagination_class = CustomPagination
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter)
    filterset_fields = ['transaction_type', 'status', 'created_at']
    search_fields = ['reference', 'paystack_transaction_id']
    ordering_fields = ['amount', 'created_at', 'updated_at']
    ordering = ['-created_at']
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Return transactions for the authenticated user only."""
        return Transaction.objects.filter(user=self.request.user)

    @action(detail=False, methods=['get'], url_path='history')
    def get_history(self, request):
        """
        Get transaction history for the authenticated user.
        
        Returns formatted transaction history with additional metadata.
        """
        try:
            transactions = self.get_queryset()
            serializer = TransactionHistorySerializer(transactions, many=True)
            logger.info(f"Transaction history retrieved for user: {request.user.email}")
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error retrieving transaction history for user {request.user.email}: {str(e)}")
            return Response(
                {"message": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class WithdrawalViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Withdrawal model.
    
    Provides CRUD operations for withdrawals with user-specific filtering.
    """
    pagination_class = CustomPagination
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter)
    filterset_fields = ['status', 'bank_name', 'created_at']
    search_fields = ['bank_name', 'account_number', 'paystack_transfer_reference']
    ordering_fields = ['amount', 'created_at', 'updated_at']
    ordering = ['-created_at']
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Return withdrawals for the authenticated user only."""
        return Withdrawal.objects.filter(user=self.request.user)

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'create':
            return WithdrawalRequestSerializer
        return WithdrawalDetailSerializer

    def perform_create(self, serializer):
        """Log withdrawal creation."""
        withdrawal = serializer.save()
        logger.info(f"Withdrawal created for user: {withdrawal.user.email}")

    def perform_update(self, serializer):
        """Log withdrawal updates."""
        withdrawal = serializer.save()
        logger.info(f"Withdrawal updated for user: {withdrawal.user.email}")

    def perform_destroy(self, instance):
        """Log withdrawal deletion."""
        user_email = instance.user.email
        instance.delete()
        logger.info(f"Withdrawal deleted for user: {user_email}")


class BankViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for Bank model.
    
    Provides read-only operations for banks with public access.
    """
    queryset = Bank.objects.filter(is_active=True)
    serializer_class = BankSerializer
    permission_classes = [AllowAny]
    pagination_class = CustomPagination
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter)
    filterset_fields = ['is_active']
    search_fields = ['name', 'code']
    ordering_fields = ['name', 'code']
    ordering = ['name']

    @action(detail=False, methods=['get'], url_path='active')
    def get_active_banks(self, request):
        """
        Get all active banks.
        
        Returns list of banks available for withdrawals.
        """
        try:
            banks = Bank.objects.filter(is_active=True)
            serializer = self.get_serializer(banks, many=True)
            logger.info("Active banks retrieved")
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error retrieving active banks: {str(e)}")
            return Response(
                {"message": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

