"""
Wallet services layer – wraps our MonnifyDedicatedAccountService
"""
import os
from decimal import Decimal
from typing import Dict

from Movr import settings

from .monnify import MonnifyError
from .monnify_service import DedicatedAccountService   # the file we built earlier
from Api.models import Wallet, Transaction, Withdrawal, Bank
from Api.models import KYC, User

# ---- singleton service instance ---- #
DEDICATED_SERVICE = DedicatedAccountService(
    api_key=settings.MONNIFY_API_KEY,
    secret=settings.MONNIFY_SECRET_KEY,
    sandbox=settings.MONNIFY_SANDBOX,
)

# ---- helper to map Monnify bank → local Bank instance ---- #
def _get_or_create_bank(bank_name: str, bank_code: str) -> Bank:
    """
    Synchronizes a bank from Monnify API using the unique 'code' as the primary key.
    
    If the bank exists by code, it updates the name (in case of changes).
    If it doesn't exist, it creates a new one.
    """
    bank, _ = Bank.objects.get_or_create(
        # 1. Lookup by the unique code
        code=bank_code,
        # 2. Set/update the following fields
        defaults={'name': bank_name}
        # Note: 'name' is unique, but we are looking up by 'code'. 
        # Django will first check if `code=bank_code` exists. 
        # If it does, it updates `name`. If not, it creates a new one 
        # with both `code` and `name`.
    )
    return bank


# ---- public helpers used by views / signals ---- #
def create_dedicated_account_for_user(user: User) -> Dict:
    """
    Calls Monnify sandbox API and persists the returned account data
    into the Wallet model (one-time on registration).
    """
    kyc, created = KYC.objects.get_or_create(user=user)
    # create account
    acc = DEDICATED_SERVICE.create_account(
        account_name=f"{user.first_name}{user.last_name}".strip(),
        customer_email=user.email,
        contract_code=settings.MONNIFY_CONTRACT_CODE,
        bvn=kyc.bvn
    )

    # persist to wallet
    wallet, _ = Wallet.objects.get_or_create(user=user)
    wallet.dva_account_number = acc.account_number
    wallet.dva_account_name = acc.account_name
    wallet.dva_bank_name = acc.bank_name
    wallet.dva_account_reference = acc.account_reference
    wallet.save(update_fields=["dva_account_number", "dva_account_name", "dva_bank_name", "dva_account_reference"])

    return acc.to_dict()


def fetch_reserved_account_details(user: User) -> Dict:
    """
    Retrieves the full details of a user's existing Dedicated Virtual Account (DVA) 
    from Monnify. This is useful for confirming the 'incomeSplitConfig' setup.

    :param user: The User instance whose DVA details are being retrieved.
    :return: Dictionary of account details or None if DVA not found/not set up.
    """
    try:
        wallet = Wallet.objects.get(user=user)
    except Wallet.DoesNotExist:
        return None

    if not wallet.dva_account_number:
        return None

    try:
        # Assuming the DEDICATED_SERVICE exposes a method to fetch details by the DVA Account Number
        # Monnify often uses the 'accountReference' (which could be the user ID) for lookups.
        # We will use the account number for this example.
        account_details = DEDICATED_SERVICE.fetch_account_details(
            account_reference=wallet.dva_account_reference
        )
        return account_details
    except MonnifyError as e:
        # Handle cases where the DVA might not exist on Monnify's side
        if 'not found' in str(e).lower():
            return None
        raise ValueError(f"Failed to fetch DVA details: {str(e)}")


def fetch_balance_from_monnify(wallet: Wallet) -> Decimal:
    """
    Calls Monnify to get the *actual* balance on the dedicated account.
    For deposits we’ll rely on webhooks, so this is mostly for sanity checks.
    """
    # Monnify does not expose a “reserved account balance” endpoint.
    # In practice, we trust our local Wallet.balance updated by webhooks.
    # This method is a placeholder if Monnify ever adds such an endpoint.
    return wallet.balance


def initiate_withdrawal(
    user: User,
    amount: Decimal,
    bank_name: str,
    account_number: str,
) -> str:
    """
    Uses the service to withdraw from the user’s dedicated account
    and returns the Monnify transaction reference.
    """
    wallet = Wallet.objects.get(user=user)
    if wallet.balance < amount:
        raise ValueError("Insufficient balance")

    tx_ref = DEDICATED_SERVICE.withdraw(
        source_account=settings.MONNIFY_MAIN_ACCOUNT_NUMBER,  # your Monnify wallet
        destination_account=account_number,
        destination_bank_code=_get_or_create_bank(bank_name, "").code,
        amount=float(amount),
        narration=f"Withdrawal for {user.email}",
    )

    # record locally
    Withdrawal.objects.create(
        user=user,
        bank_name=bank_name,
        account_number=account_number,
        amount=amount,
        transfer_reference=tx_ref,
        status="processing",
    )
    Transaction.objects.create(
        user=user,
        transaction_type="withdrawal",
        amount=amount,
        reference=tx_ref,
        status="processing",
    )

    # deduct immediately (webhook will finalize)
    wallet.deduct_funds(amount)

    return tx_ref

def update_bvn_on_reserved_account(user: User, bvn: str) -> None:
    """
    PATCH the BVN to the existing reserved account.
    """
    wallet = Wallet.objects.get(user=user)
    if not wallet.dva_account_number:
        raise ValueError("No dedicated account exists for this user")

    token = DEDICATED_SERVICE._ensure_token()
    try:
        DEDICATED_SERVICE.update_bvn_on_reserved_account(
            token,
            account_reference=wallet.dva_account_reference,  # or whatever you stored
            bvn=bvn,
        )
    except MonnifyError as e:
        raise ValueError(str(e))
    

def get_active_banks() -> Dict[str, str]:
    """
    Fetches the list of active banks from the local DB.
    """
    try:
        banks = DEDICATED_SERVICE.fetch_banks()
        for bank in banks:
            _get_or_create_bank(bank_name=bank["name"], bank_code=bank["code"])

        active_banks = Bank.objects.filter(is_active=True).values("name", "code")
        return {bank["name"]: bank["code"] for bank in active_banks}
    except MonnifyError as e:
        raise ValueError(str(e))
    

def validate_account_details(bank_code: str, account_number: str) -> str:
    """
    Validates the account number and bank code via Monnify.
    Returns the account name if valid, else raises ValueError.
    """
    try:
        account_details = DEDICATED_SERVICE.validate_account(
            bank_code=bank_code,
            account_number=account_number,
        )
        return account_details
    except MonnifyError as e:
        raise ValueError(str(e))

# --- NEW FUNCTION REQUIRED BY CRON JOB ---
def check_transfer_status(reference: str) -> Dict:
    """
    Checks the status of a Monnify transfer (Disbursement) using its reference.
    This is used by the background job to update local records.
    
    Returns a dictionary containing the Monnify status details.
    
    NOTE: This assumes DEDICATED_SERVICE.transction_status returns 
    the status under the key 'payment_status'.
    """
    try:
        # Call the underlying service method provided by the user
        status_data = DEDICATED_SERVICE.transaction_status(
            transaction_reference=reference
        )
        
        # We extract the status from the key defined in the service method provided by the user
        monnify_status = status_data.get("payment_status", "PENDING").upper()
        
        # The management command expects a top-level 'status' key for mapping
        status_data['status'] = monnify_status
        return status_data
        
    except MonnifyError as e:
        # Log the error and return a standard failure dictionary
        print(f"Monnify check status failed for {reference}: {str(e)}")
        return {"status": "EXTERNAL_ERROR", "message": str(e)}
    