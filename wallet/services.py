"""
Wallet services layer – wraps our MonnifyDedicatedAccountService
"""
import os
from decimal import Decimal
from typing import Dict

from .monnify import MonnifyError
from .monnify_service import DedicatedAccountService   # the file we built earlier
from wallet.models import Wallet, Transaction, Withdrawal, Bank
from Api.models import CustomUser as User

from decouple import config

# ---- singleton service instance ---- #
DEDICATED_SERVICE = DedicatedAccountService(
    api_key=config("MONNIFY_API_KEY"),
    secret=config("MONNIFY_SECRET_KEY"),
    sandbox=config("MONNIFY_SANDBOX"),
)

# ---- helper to map Monnify bank → local Bank instance ---- #
def _get_or_create_bank(bank_name: str, bank_code: str) -> Bank:
    bank, _ = Bank.objects.get_or_create(
        code=bank_code,
        defaults={"name": bank_name, "is_active": True},
    )
    return bank


# ---- public helpers used by views / signals ---- #
def create_dedicated_account_for_user(user: User) -> Dict:
    """
    Calls Monnify sandbox API and persists the returned account data
    into the Wallet model (one-time on registration).
    """
    # create account
    acc = DEDICATED_SERVICE.create_account(
        account_name=f"{user.first_name} {user.last_name}".strip(),
        customer_email=user.email,
        customer_name=f"{user.first_name} {user.last_name}".strip(),
        contract_code=os.environ["MONNIFY_CONTRACT_CODE"],
        bvn=None,
    )

    # persist to wallet
    wallet, _ = Wallet.objects.get_or_create(user=user)
    wallet.dva_account_number = acc.account_number
    wallet.dva_account_name = acc.account_name
    wallet.dva_bank_name = acc.bank_name
    wallet.save(update_fields=["dva_account_number", "dva_account_name", "dva_bank_name"])

    return acc.to_dict()


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
        source_account="YOUR_WALLET_SETTLEMENT_ACCOUNT",  # your Monnify wallet
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
        paystack_transfer_reference=tx_ref,
        status="Processing",
    )
    Transaction.objects.create(
        user=user,
        transaction_type="withdrawal",
        amount=amount,
        reference=tx_ref,
        status="Processing",
    )

    # deduct immediately (webhook will finalize)
    wallet.balance -= amount
    wallet.save(update_fields=["balance"])

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
            account_reference=wallet.user.id,  # or whatever you stored
            bvn=bvn,
        )
    except MonnifyError as e:
        raise ValueError(str(e))