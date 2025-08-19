"""
Wallet views – thin wrappers that delegate to wallet/services.py
"""
from decimal import Decimal
import hmac
import hashlib
import os
from django.http import HttpResponse
from django.utils import timezone
import json # Import json for Paystack response parsing

from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction as db_transaction
from django.db.models import Q

from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from Api.views import get_user_from_token
from Api.models import Notification
from wallet.models import Wallet, Transaction, Withdrawal, Bank
from wallet.serializers import (
    WalletSerializer, # Use WalletSerializer for full wallet details
    TransactionSerializer,
    WithdrawalRequestSerializer, # For user input
)
from Api.models import CustomUser as User # Ensure User model is correctly imported

from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from wallet.services import (
    create_dedicated_account_for_user,
    fetch_balance_from_monnify,
    initiate_withdrawal,
)

import logging

logger = logging.getLogger(__name__)

MONNIFY_SECRET_KEY = os.environ.get("MONNIFY_SECRET_KEY")

class WalletDetailsView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = get_user_from_token(request)
        wallet, _ = Wallet.objects.get_or_create(user=user)
        data = WalletSerializer(wallet).data
        # Optionally enrich with Monnify account details
        return Response({"wallet": data}, status=status.HTTP_200_OK)


class AllTransactionsView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = get_user_from_token(request)
        txs = Transaction.objects.filter(user=user).order_by("-created_at")
        return Response(
            {"transactions": TransactionSerializer(txs, many=True).data},
            status=status.HTTP_200_OK,
        )


class TransactionDetailView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated] # Enable permission

    def get(self, request, pk): # Use 'pk' (primary key) for detail view conventions
        try:
            user = get_user_from_token(request)

            # Fetch the specific transaction for the user
            # Use get_object_or_404 for cleaner error handling
            transaction = Transaction.objects.get(Q(id=pk) & Q(user=user))
            transaction_data = TransactionSerializer(transaction).data

            logger.info(f"Transaction detail retrieved for user: {user.email}")
            return Response({"transaction": transaction_data}, status=status.HTTP_200_OK)

        except Transaction.DoesNotExist:
            logger.warning(f"Transaction not found or does not belong to user: {user.email if 'user' in locals() else 'unknown'}")
            return Response({"message": "Transaction not found or does not belong to this user."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e: # Catch other potential errors like invalid UUID if pk is UUIDField
            logger.error(f"Unexpected error fetching transaction detail: {str(e)}")
            return Response({"message": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class WithdrawalRequestView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

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
        


@method_decorator(csrf_exempt, name='dispatch') # Disable CSRF for webhook endpoint
class MonnifyWebhookView(APIView):
    authentication_classes = [] # No authentication for webhooks
    permission_classes = []     # No permissions for webhooks

    def post(self, request, *args, **kwargs):
        # 1. Verify Webhook Signature
        paystack_signature = request.headers.get('x-paystack-signature')
        if not paystack_signature:
            logger.warning("No X-Paystack-Signature header in webhook request.")
            return HttpResponse(status=status.HTTP_400_BAD_REQUEST, content="No X-Paystack-Signature header.")

        # Get raw request body (important for signature verification)
        raw_payload = request.body.decode('utf-8')

        # Hash the payload with your secret key
        digest = hmac.new(
            MONNIFY_SECRET_KEY.encode('utf-8'),
            raw_payload.encode('utf-8'),
            hashlib.sha512
        ).hexdigest()

        if digest != paystack_signature:
            logger.warning("Webhook signature mismatch. Potential tampering detected.")
            return HttpResponse(status=status.HTTP_403_FORBIDDEN, content="Invalid webhook signature.")

        # 2. Parse the Event Data
        try:
            event = json.loads(raw_payload)
        except json.JSONDecodeError:
            logger.error("Invalid JSON payload in webhook request.")
            return HttpResponse(status=status.HTTP_400_BAD_REQUEST, content="Invalid JSON payload.")

        event_type = event.get('event')
        event_data = event.get('data')

        if not event_type or not event_data:
            logger.warning("Invalid event data structure in webhook request.")
            return HttpResponse(status=status.HTTP_400_BAD_REQUEST, content="Invalid event data structure.")

        # Paystack expects a 200 OK response quickly, even if processing takes time.
        # For complex logic, you'd send 200 OK immediately and offload processing to a task queue.
        # For this example, we'll process synchronously.
        try:
            if event_type == 'charge.success':
                self._handle_charge_success(event_data)
            elif event_type == 'transfer.success':
                self._handle_transfer_success(event_data)
            elif event_type == 'transfer.failed':
                self._handle_transfer_failed(event_data)
            elif event_type == 'transfer.reversed':
                self._handle_transfer_reversed(event_data)
            # Add other event types if necessary (e.g., invoice.create, subscription.update)
            else:
                logger.info(f"Unhandled Paystack event type: {event_type}")

            return HttpResponse(status=status.HTTP_200_OK) # Acknowledge receipt
        except Exception as e:
            # Log the error, but still return 200 to Paystack to prevent retries
            # For debugging, you might temporarily return 500, but in production, 200 is safer.
            logger.error(f"Error processing Paystack webhook event {event_type}: {e}")
            return HttpResponse(status=status.HTTP_200_OK) # Still return 200 to Paystack


    def _handle_charge_success(self, data):
        """
        Handles successful deposit events (e.g., from Dedicated Virtual Accounts).
        """
        reference = data.get('reference')
        amount_kobo = data.get('amount') # Amount in kobo/pesewas
        status = data.get('status')
        customer_email = data.get('customer', {}).get('email')
        paystack_transaction_id = data.get('id')
        paid_at = data.get('paid_at') # Payment timestamp

        if status != 'success':
            logger.warning(f"Charge not successful for reference {reference}, status: {status}")
            return

        amount = Decimal(amount_kobo) / 100 # Convert kobo to your currency unit

        with db_transaction.atomic():
            # Check for idempotency: Has this transaction already been processed?
            if Transaction.objects.filter(reference=reference, status='Completed').exists():
                logger.info(f"Deposit with reference {reference} already processed. Skipping.")
                return

            try:
                # Find user by email (or by customer_code if stored on User model directly)
                user = User.objects.get(email=customer_email)
                wallet = Wallet.objects.select_for_update().get(user=user)

                wallet.balance += amount
                wallet.save(update_fields=['balance'])

                transaction, created = Transaction.objects.get_or_create(
                    reference=reference, # Use reference for uniqueness
                    defaults={
                        'user': user,
                        'transaction_type': 'Deposit',
                        'amount': amount,
                        'status': 'Completed',
                        'paystack_transaction_id': paystack_transaction_id,
                        'created_at': timezone.datetime.fromisoformat(paid_at.replace('Z', '+00:00')) if paid_at else timezone.now(),
                    }
                )
                if not created:
                    # If transaction already existed but wasn't 'Completed' (e.g., failed retry)
                    transaction.status = 'Completed'
                    transaction.paystack_transaction_id = paystack_transaction_id
                    transaction.save(update_fields=['status', 'paystack_transaction_id'])

                Notification.objects.create(
                    user=user,
                    title="Deposit Successful",
                    message=f"A deposit of {amount} has been successfully added to your wallet. Ref: {reference}"
                )
                logger.info(f"Successfully processed deposit for {user.email}, amount {amount}, ref {reference}")

            except User.DoesNotExist:
                logger.error(f"User not found for email: {customer_email}. Cannot process deposit {reference}.")
                # Handle this: maybe create a user? Log a critical error?
            except Wallet.DoesNotExist:
                logger.error(f"Wallet not found for user: {customer_email}. Cannot process deposit {reference}.")
                # This should ideally not happen if you create wallets with users
            except Exception as e:
                logger.error(f"Error handling charge.success for {reference}: {e}")
                raise # Re-raise to ensure transaction rollback if within atomic block

    def _handle_transfer_success(self, data):
        """
        Handles successful withdrawal (transfer) events.
        """
        reference = data.get('reference')
        amount_kobo = data.get('amount')
        paystack_transfer_id = data.get('id')

        amount = Decimal(amount_kobo) / 100

        with db_transaction.atomic():
            try:
                # Find the corresponding Withdrawal request
                withdrawal = Withdrawal.objects.select_for_update().get(
                    paystack_transfer_reference=reference
                )

                if withdrawal.status == 'Completed':
                    logger.info(f"Withdrawal {reference} already marked as completed. Skipping.")
                    return

                withdrawal.status = 'Completed'
                withdrawal.updated_at = timezone.now()
                withdrawal.save(update_fields=['status', 'updated_at'])

                # Update the corresponding Transaction
                transaction = Transaction.objects.get(
                    user=withdrawal.user,
                    transaction_type='Withdrawal',
                    reference=reference # Match by the same reference
                )
                transaction.status = 'Completed'
                transaction.updated_at = timezone.now()
                transaction.save(update_fields=['status', 'updated_at'])

                Notification.objects.create(
                    user=withdrawal.user,
                    title="Withdrawal Completed",
                    message=f"Your withdrawal of {amount} has been successfully processed."
                )
                logger.info(f"Successfully processed successful transfer for {reference}")

            except Withdrawal.DoesNotExist:
                logger.warning(f"Withdrawal request with reference {reference} not found. Could not update status.")
            except Transaction.DoesNotExist:
                logger.warning(f"Transaction for withdrawal {reference} not found. Data inconsistency.")
            except Exception as e:
                logger.error(f"Error handling transfer.success for {reference}: {e}")
                raise

    def _handle_transfer_failed(self, data):
        """
        Handles failed withdrawal (transfer) events. Funds are NOT returned by Paystack.
        This means the funds were deducted from your Paystack balance but didn't reach the recipient.
        You might need to manually reconcile or contact Paystack support.
        From a user's wallet perspective, their balance was already reduced, and it should remain so.
        """
        reference = data.get('reference')
        fail_reason = data.get('transfer_code_reason') or data.get('status') or 'Unknown reason'
        amount_kobo = data.get('amount')
        
        amount = Decimal(amount_kobo) / 100

        with db_transaction.atomic():
            try:
                withdrawal = Withdrawal.objects.select_for_update().get(
                    paystack_transfer_reference=reference
                )

                if withdrawal.status == 'Failed':
                    logger.info(f"Withdrawal {reference} already marked as failed. Skipping.")
                    return

                withdrawal.status = 'Failed'
                withdrawal.failure_reason = f"Paystack transfer failed: {fail_reason}"
                withdrawal.updated_at = timezone.now()
                withdrawal.save(update_fields=['status', 'failure_reason', 'updated_at'])

                transaction = Transaction.objects.get(
                    user=withdrawal.user,
                    transaction_type='Withdrawal',
                    reference=reference
                )
                transaction.status = 'Failed'
                transaction.updated_at = timezone.now()
                transaction.save(update_fields=['status', 'updated_at'])

                Notification.objects.create(
                    user=withdrawal.user,
                    title="Withdrawal Failed",
                    message=f"Your withdrawal of {amount} failed. Reason: {fail_reason}. Please contact support."
                )
                logger.warning(f"Processed failed transfer for {reference}, reason: {fail_reason}")

            except Withdrawal.DoesNotExist:
                logger.warning(f"Withdrawal request with reference {reference} not found for failed event.")
            except Transaction.DoesNotExist:
                logger.warning(f"Transaction for failed withdrawal {reference} not found. Data inconsistency.")
            except Exception as e:
                logger.error(f"Error handling transfer.failed for {reference}: {e}")
                raise

    def _handle_transfer_reversed(self, data):
        """
        Handles reversed withdrawal (transfer) events.
        This means the funds were reversed back to YOUR Paystack balance.
        Crucially, you MUST credit the user's wallet back.
        """
        reference = data.get('reference')
        amount_kobo = data.get('amount')
        reverse_reason = data.get('message') or 'Unknown reason'

        amount = Decimal(amount_kobo) / 100

        with db_transaction.atomic():
            try:
                withdrawal = Withdrawal.objects.select_for_update().get(
                    paystack_transfer_reference=reference
                )

                if withdrawal.status == 'Reversed':
                    logger.info(f"Withdrawal {reference} already marked as reversed. Skipping.")
                    return

                # Update Withdrawal status
                withdrawal.status = 'Reversed'
                withdrawal.failure_reason = f"Paystack transfer reversed: {reverse_reason}"
                withdrawal.updated_at = timezone.now()
                withdrawal.save(update_fields=['status', 'failure_reason', 'updated_at'])

                # Credit user's wallet back
                user_wallet = Wallet.objects.select_for_update().get(user=withdrawal.user)
                user_wallet.balance += amount
                user_wallet.save(update_fields=['balance'])
                logger.info(f"Credited wallet of {user_wallet.user.email} with {amount} due to reversed transfer {reference}.")

                # Update the corresponding Transaction
                transaction = Transaction.objects.get(
                    user=withdrawal.user,
                    transaction_type='Withdrawal',
                    reference=reference
                )
                transaction.status = 'Reversed'
                transaction.updated_at = timezone.now()
                transaction.save(update_fields=['status', 'updated_at'])

                # Create a new deposit transaction to clearly show funds return
                Transaction.objects.create(
                    user=withdrawal.user,
                    transaction_type='Deposit',
                    amount=amount,
                    status='Completed',
                    reference=f"REVERSED-DEPOSIT-{reference}", # New unique ref for the return
                    # Link to original withdrawal if needed
                )

                Notification.objects.create(
                    user=withdrawal.user,
                    title="Withdrawal Reversed & Funds Returned",
                    message=f"Your withdrawal of {amount} was reversed. The funds have been returned to your wallet. Reason: {reverse_reason}"
                )
                logger.info(f"Processed reversed transfer for {reference}, reason: {reverse_reason}. Funds returned to wallet.")

            except Withdrawal.DoesNotExist:
                logger.warning(f"Withdrawal request with reference {reference} not found for reversed event.")
            except Transaction.DoesNotExist:
                logger.warning(f"Transaction for reversed withdrawal {reference} not found. Data inconsistency.")
            except Wallet.DoesNotExist:
                logger.critical(f"Wallet for user {withdrawal.user.email} not found for reversed transfer {reference}. Critical error.")
            except Exception as e:
                logger.error(f"Error handling transfer.reversed for {reference}: {e}")
                raise

