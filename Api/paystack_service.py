import hashlib
import hmac
import json
import logging
from decimal import Decimal
from typing import Dict, Optional, Tuple

import requests
from django.conf import settings
from django.utils import timezone

from .models import PaystackAccount, PaystackTransaction, CustomUser, Wallet, Transaction

logger = logging.getLogger(__name__)


class PaystackService:
    """
    Service class to handle Paystack API interactions
    """
    
    def __init__(self):
        self.secret_key = getattr(settings, 'PAYSTACK_SECRET_KEY', '')
        self.public_key = getattr(settings, 'PAYSTACK_PUBLIC_KEY', '')
        self.base_url = 'https://api.paystack.co'
        
        if not self.secret_key:
            raise ValueError("PAYSTACK_SECRET_KEY is required in settings")
    
    def _make_request(self, method: str, endpoint: str, data: Dict = None) -> Tuple[bool, Dict]:
        """
        Make HTTP request to Paystack API
        """
        url = f"{self.base_url}{endpoint}"
        headers = {
            'Authorization': f'Bearer {self.secret_key}',
            'Content-Type': 'application/json'
        }
        
        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=headers, json=data)
            else:
                return False, {"error": f"Unsupported HTTP method: {method}"}
            
            response.raise_for_status()
            return True, response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Paystack API request failed: {str(e)}")
            return False, {"error": str(e)}
    
    def create_customer(self, user: CustomUser) -> Tuple[bool, Dict]:
        """
        Create a Paystack customer
        """
        data = {
            'email': user.email,
            'first_name': user.first_name or '',
            'last_name': user.last_name or '',
            'phone': user.phone_number or ''
        }
        
        success, response = self._make_request('POST', '/customer', data)
        return success, response
    
    def create_dva_account(self, user: CustomUser, preferred_bank: str = None) -> Tuple[bool, Dict]:
        """
        Create a Direct Virtual Account for the user
        """
        # First, create or get customer
        success, customer_response = self.create_customer(user)
        if not success:
            return False, customer_response
        
        customer_code = customer_response.get('data', {}).get('customer_code')
        if not customer_code:
            return False, {"error": "Failed to get customer code"}
        
        # Create DVA account
        dva_data = {
            'customer': customer_code,
            'preferred_bank': preferred_bank,
            'subaccount': getattr(settings, 'PAYSTACK_SUBACCOUNT_CODE', ''),
            'split_code': getattr(settings, 'PAYSTACK_SPLIT_CODE', '')
        }
        
        success, dva_response = self._make_request('POST', '/dedicated_account', dva_data)
        
        if success:
            # Save account details to database
            account_data = dva_response.get('data', {})
            PaystackAccount.objects.update_or_create(
                user=user,
                defaults={
                    'account_number': account_data.get('account_number'),
                    'bank_name': account_data.get('bank', {}).get('name'),
                    'bank_code': account_data.get('bank', {}).get('code'),
                    'paystack_customer_code': customer_code,
                    'paystack_account_id': account_data.get('id'),
                    'status': 'active',
                    'is_active': True
                }
            )
        
        return success, dva_response
    
    def verify_transaction(self, reference: str) -> Tuple[bool, Dict]:
        """
        Verify a Paystack transaction
        """
        success, response = self._make_request('GET', f'/transaction/verify/{reference}')
        return success, response
    
    def initiate_transfer(self, recipient_code: str, amount: Decimal, reason: str = None) -> Tuple[bool, Dict]:
        """
        Initiate a transfer to a recipient
        """
        data = {
            'source': 'balance',
            'amount': int(amount * 100),  # Convert to kobo
            'recipient': recipient_code,
            'reason': reason or 'Transfer'
        }
        
        success, response = self._make_request('POST', '/transfer', data)
        return success, response
    
    def get_banks(self) -> Tuple[bool, Dict]:
        """
        Get list of available banks
        """
        success, response = self._make_request('GET', '/bank')
        return success, response
    
    def resolve_account_number(self, account_number: str, bank_code: str) -> Tuple[bool, Dict]:
        """
        Resolve account number to get account details
        """
        data = {
            'account_number': account_number,
            'bank_code': bank_code
        }
        
        success, response = self._make_request('POST', '/bank/resolve', data)
        return success, response
    
    def create_recipient(self, account_number: str, bank_code: str, name: str) -> Tuple[bool, Dict]:
        """
        Create a transfer recipient
        """
        data = {
            'type': 'nuban',
            'name': name,
            'account_number': account_number,
            'bank_code': bank_code,
            'currency': 'NGN'
        }
        
        success, response = self._make_request('POST', '/transferrecipient', data)
        return success, response
    
    def verify_webhook_signature(self, payload: str, signature: str) -> bool:
        """
        Verify webhook signature to ensure it's from Paystack
        """
        try:
            # Create HMAC SHA512 hash
            hash = hmac.new(
                self.secret_key.encode('utf-8'),
                payload.encode('utf-8'),
                hashlib.sha512
            ).hexdigest()
            
            return hmac.compare_digest(hash, signature)
        except Exception as e:
            logger.error(f"Error verifying webhook signature: {str(e)}")
            return False
    
    def process_webhook(self, payload: Dict, signature: str) -> bool:
        """
        Process Paystack webhook
        """
        # Verify signature
        if not self.verify_webhook_signature(json.dumps(payload), signature):
            logger.error("Invalid webhook signature")
            return False
        
        event = payload.get('event')
        data = payload.get('data', {})
        
        if event == 'charge.success':
            return self._handle_successful_charge(data)
        elif event == 'transfer.success':
            return self._handle_successful_transfer(data)
        elif event == 'transfer.failed':
            return self._handle_failed_transfer(data)
        else:
            logger.info(f"Unhandled webhook event: {event}")
            return True
    
    def _handle_successful_charge(self, data: Dict) -> bool:
        """
        Handle successful charge webhook
        """
        try:
            reference = data.get('reference')
            if not reference:
                logger.error("No reference found in charge data")
                return False
            
            # Get or create PaystackTransaction
            transaction, created = PaystackTransaction.objects.get_or_create(
                paystack_reference=reference,
                defaults={
                    'user': self._get_user_from_reference(reference),
                    'transaction_type': 'deposit',
                    'amount': Decimal(data.get('amount', 0)) / 100,  # Convert from kobo
                    'status': 'success',
                    'gateway_response': data.get('gateway_response', ''),
                    'channel': data.get('channel', ''),
                    'paid_at': timezone.now()
                }
            )
            
            if not created:
                # Update existing transaction
                transaction.status = 'success'
                transaction.paid_at = timezone.now()
                transaction.save()
            
            # Update user's wallet
            self._update_user_wallet(transaction.user, transaction.amount, 'deposit')
            
            logger.info(f"Successfully processed charge for reference: {reference}")
            return True
            
        except Exception as e:
            logger.error(f"Error handling successful charge: {str(e)}")
            return False
    
    def _handle_successful_transfer(self, data: Dict) -> bool:
        """
        Handle successful transfer webhook
        """
        try:
            transfer_id = data.get('id')
            if not transfer_id:
                logger.error("No transfer ID found in transfer data")
                return False
            
            # Update PaystackTransaction if it exists
            try:
                transaction = PaystackTransaction.objects.get(
                    paystack_transaction_id=transfer_id
                )
                transaction.status = 'success'
                transaction.save()
                
                logger.info(f"Successfully processed transfer: {transfer_id}")
                return True
                
            except PaystackTransaction.DoesNotExist:
                logger.warning(f"Transfer transaction not found: {transfer_id}")
                return True
                
        except Exception as e:
            logger.error(f"Error handling successful transfer: {str(e)}")
            return False
    
    def _handle_failed_transfer(self, data: Dict) -> bool:
        """
        Handle failed transfer webhook
        """
        try:
            transfer_id = data.get('id')
            if not transfer_id:
                logger.error("No transfer ID found in failed transfer data")
                return False
            
            # Update PaystackTransaction if it exists
            try:
                transaction = PaystackTransaction.objects.get(
                    paystack_transaction_id=transfer_id
                )
                transaction.status = 'failed'
                transaction.gateway_response = data.get('failure_reason', '')
                transaction.save()
                
                logger.info(f"Successfully processed failed transfer: {transfer_id}")
                return True
                
            except PaystackTransaction.DoesNotExist:
                logger.warning(f"Transfer transaction not found: {transfer_id}")
                return True
                
        except Exception as e:
            logger.error(f"Error handling failed transfer: {str(e)}")
            return False
    
    def _get_user_from_reference(self, reference: str) -> Optional[CustomUser]:
        """
        Get user from transaction reference
        """
        try:
            # Try to find existing transaction
            transaction = PaystackTransaction.objects.get(paystack_reference=reference)
            return transaction.user
        except PaystackTransaction.DoesNotExist:
            # If no transaction exists, we can't determine the user
            # This should be handled by the calling code
            return None
    
    def _update_user_wallet(self, user: CustomUser, amount: Decimal, transaction_type: str):
        """
        Update user's wallet balance
        """
        try:
            wallet, created = Wallet.objects.get_or_create(user=user)
            
            if transaction_type == 'deposit':
                wallet.deposit(amount)
            elif transaction_type == 'withdrawal':
                wallet.withdraw(amount)
            
            # Create transaction record
            Transaction.objects.create(
                user=user,
                transaction_type=transaction_type,
                amount=amount,
                description=f"Paystack {transaction_type}"
            )
            
        except Exception as e:
            logger.error(f"Error updating user wallet: {str(e)}")
            raise


# Global instance
paystack_service = PaystackService() 