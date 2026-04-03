"""
Wallet views – thin wrappers that delegate to wallet/services.py
"""
import base64
from decimal import Decimal
import hmac
import hashlib
import os
from django.http import HttpResponse
from django.utils import timezone
import json

from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction as db_transaction
from django.db.models import Q

from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, OpenApiExample

from Auth.views import get_user_from_token
from Profile.models import Notification
from wallet.models import Wallet, Transaction
from wallet.serializers import (
    WalletSerializer,
    TransactionSerializer,
    WithdrawalRequestSerializer,
)
from Auth.models import CustomUser as User


import logging

from wallet.services import get_active_banks, initiate_withdrawal, validate_account_details

logger = logging.getLogger(__name__)

MONNIFY_SECRET_KEY = os.environ.get("MONNIFY_SECRET_KEY")

def _verify_monnify_signature(request_body: bytes, signature_header: str) -> bool:
    """
    Monnify sends:
        monnify-signature: t=<epoch-ms>,v1=<hex_hmac_sha512>
    """
    if not signature_header:
        return False

    digest = hmac.new(
        MONNIFY_SECRET_KEY.encode("utf-8"),
        request_body,
        hashlib.sha256
    ).digest()

    expected = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(expected, signature_header)


class WalletDetailsView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: dict},
        tags=['Wallet'],
    )
    def get(self, request):
        user = get_user_from_token(request)
        wallet, _ = Wallet.objects.get_or_create(user=user)

        try:
            transactions = Transaction.objects.filter(user=user).order_by('-created_at')[:5]
            transactions_data = TransactionSerializer(transactions, many=True).data
        except Exception as e:
            transactions_data = []

        wallet_data = WalletSerializer(wallet).data
        
        return Response({"wallet_details": wallet_data,
            "recent_transactions": transactions_data,}, status=status.HTTP_200_OK)


class AllTransactionsView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: dict},
        tags=['Wallet'],
    )
    def get(self, request):
        user = get_user_from_token(request)
        wallet, _ = Wallet.objects.get_or_create(user=user)

        try:
            # Fetch last 5 transactions
            transactions = Transaction.objects.filter(user=user).order_by('-created_at')[:5]
            transactions_data = TransactionSerializer(transactions, many=True).data
        except Exception as e:
            transactions_data = []

        wallet_data = WalletSerializer(wallet).data
        
        return Response({"wallet_details": wallet_data,
            "recent_transactions": transactions_data,}, status=status.HTTP_200_OK)


class AllTransactionsView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = TransactionSerializer

    @extend_schema(
        responses={200: dict},
        tags=['Wallet'],
    )
    def get(self, request):
        user = get_user_from_token(request)
        txs = Transaction.objects.filter(user=user).order_by("-created_at")
        return Response(
            {"transactions": TransactionSerializer(txs, many=True).data},
            status=status.HTTP_200_OK,
        )

@method_decorator(cache_page(60 * 2), name='get')
class TransactionDetailView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: dict, 404: dict},
        tags=['Wallet'],
    )
    def get(self, request, pk):
        try:
            user = get_user_from_token(request)
            transaction = Transaction.objects.get(Q(id=pk) & Q(user=user))
            transaction_data = TransactionSerializer(transaction).data

            logger.info(f"Transaction detail retrieved for user: {user.email}")
            return Response({"transaction": transaction_data}, status=status.HTTP_200_OK)

        except Transaction.DoesNotExist:
            logger.warning(f"Transaction not found or does not belong to user: {user.email if 'user' in locals() else 'unknown'}")
            return Response({"message": "Transaction not found or does not belong to this user."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Unexpected error fetching transaction detail: {str(e)}")
            return Response({"message": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class WithdrawalRequestView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=WithdrawalRequestSerializer,
        responses={201: dict, 400: dict},
        tags=['Wallet'],
    )
    def post(self, request):
        user = get_user_from_token(request)
        serializer = WithdrawalRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            tx_ref = initiate_withdrawal(
                user=user,
                amount=Decimal(serializer.validated_data["amount"]),
                bank_name=serializer.validated_data["bank_name"],
                account_number=serializer.validated_data["account_number"],
            )
            return Response({"reference": tx_ref}, status=status.HTTP_201_CREATED)
        except ValueError as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        


@method_decorator(csrf_exempt, name='dispatch')
class MonnifyWebhookView(APIView):
    """
    Webhook endpoint for Monnify payment notifications.
    
    No authentication required - Monnify signs the payload instead.
    """
    authentication_classes = []
    permission_classes = [AllowAny]

    @extend_schema(
        request=dict,
        responses={200: dict, 400: dict, 403: dict},
        tags=['Wallet'],
    )
    def post(self, request, *args, **kwargs):
        sig = request.headers.get("monnify-signature")
        if not _verify_monnify_signature(request.body, sig):
            logger.warning("Monnify webhook signature invalid.")
            return HttpResponse(status=status.HTTP_403_FORBIDDEN, content="Bad signature")

        try:
            payload = json.loads(request.body)
        except json.JSONDecodeError:
            logger.error("Invalid JSON in Monnify webhook.")
            return HttpResponse(status=status.HTTP_400_BAD_REQUEST, content="Bad JSON")

        event_type = payload.get("eventType")
        data = payload.get("eventData")

        if not event_type or not data:
            return HttpResponse(status=status.HTTP_400_BAD_REQUEST, content="Bad payload")

        # Monnify expects 200 immediately
        try:
            if event_type == "SUCCESSFUL_TRANSACTION":
                self._handle_successful_transaction(data)
            elif event_type == "FAILED_TRANSACTION":
                self._handle_failed_transaction(data)
            elif event_type == "REVERSED_TRANSACTION":
                self._handle_reversed_transaction(data)
            else:
                logger.info(f"Unhandled Monnify event: {event_type}")

            return HttpResponse(status=status.HTTP_200_OK)

        except Exception as exc:
            logger.exception("Error processing Monnify webhook: %s", exc)
            return HttpResponse(status=status.HTTP_200_OK)  # do not retry

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------
    def _handle_successful_transaction(self, data: dict):
        """
        Deposit (incoming funds) – covers reserved-account and card payments.
        """
        reference = data["paymentReference"]  # your internal ref
        amount = Decimal(str(data["amountPaid"]))
        customer_email = data["customer"]["email"]
        txn_ref = data["transactionReference"]  # Monnify’s own ref

        with db_transaction.atomic():
            if Transaction.objects.filter(reference=reference, status="Completed").exists():
                logger.info("Deposit %s already processed.", reference)
                return

            try:
                user = User.objects.get(email=customer_email)
                wallet = Wallet.objects.select_for_update().get(user=user)

                wallet.balance += amount
                wallet.save(update_fields=["balance"])

                Transaction.objects.create(
                    user=user,
                    transaction_type="deposit",
                    amount=amount,
                    status="completed",
                    reference=reference,
                    monnify_transaction_id=txn_ref,
                    created_at=timezone.now(),
                )

                Notification.objects.create(
                    user=user,
                    title="Deposit Successful",
                    message=f"Your wallet has been credited with {amount}. Ref: {reference}",
                )
                logger.info("Deposit processed for %s – %s", user.email, reference)

            except User.DoesNotExist:
                logger.error("User %s not found for deposit %s", customer_email, reference)

    def _handle_failed_transaction(self, data: dict):
        """
        Failed deposit – typically no-op for the wallet, but you can log it.
        """
        reference = data["paymentReference"]
        logger.warning("Monnify reported failed deposit %s", reference)

    def _handle_reversed_transaction(self, data: dict):
        """
        Withdrawal was reversed – credit the wallet back.
        """
        reference = data["paymentReference"]  # original withdrawal ref
        amount = Decimal(str(data["amountPaid"]))
        reason = data.get("message", "Reversed by Monnify")

        with db_transaction.atomic():
            try:
                txn = Transaction.objects.select_for_update().get(
                    reference=reference,
                    transaction_type="withdrawal",
                )
                if txn.status == "reversed":
                    logger.info("Reversal %s already handled.", reference)
                    return

                wallet = Wallet.objects.select_for_update().get(user=txn.user)
                wallet.balance += amount
                wallet.save(update_fields=["balance"])

                txn.status = "reversed"
                txn.save(update_fields=["status"])

                # Optionally create a new deposit record
                Transaction.objects.create(
                    user=txn.user,
                    transaction_type="deposit",
                    amount=amount,
                    status="completed",
                    reference=f"REVERSED-{reference}",
                )

                Notification.objects.create(
                    user=txn.user,
                    title="Withdrawal Reversed",
                    message=f"Withdrawal {reference} was reversed and {amount} returned to your wallet. Reason: {reason}",
                )
                logger.info("Reversal processed for %s – %s", txn.user.email, reference)

            except Transaction.DoesNotExist:
                logger.error("No matching withdrawal %s for reversal.", reference)

@method_decorator(cache_page(60 * 2), name='get')
class FetchBanksView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    @extend_schema(
        responses={200: dict},
        tags=['Wallet'],
    )
    def get(self, request, *args, **kwargs):
        bank_list = get_active_banks()
        return Response({"banks": bank_list}, status=status.HTTP_200_OK)
    
class ValidateAccountView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    @extend_schema(
        request=dict,
        responses={200: dict, 400: dict},
        tags=['Wallet'],
    )
    def post(self, request, *args, **kwargs):
        account_number = request.data.get("account_number")
        bank_code = request.data.get("bank_code")

        if not account_number or not bank_code:
            return Response({"message": "account_number and bank_code are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            account_details = validate_account_details(account_number=account_number, bank_code=bank_code)
            return Response({"account_details": account_details}, status=status.HTTP_200_OK)
        except ValueError as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

