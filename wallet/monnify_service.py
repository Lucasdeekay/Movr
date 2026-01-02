"""
monnify_service.py
----------------------------
High-level helper library for Monnify **reserved (dedicated) accounts**.

Features
--------
1. Create & fetch dedicated accounts
2. Receive deposits (webhook) & expose balance
3. Withdraw from the account (Monnify disbursement)
4. Query transaction history
5. Thin wallet abstraction (crud operations)

Author : PappyCoder
Date   : 2024-08-16
"""

from __future__ import annotations

import datetime as _dt
import uuid
from typing import Dict, List, Optional

from .monnify import Monnify  # our low-level client

import logging

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#                               Exceptions                                    #
# --------------------------------------------------------------------------- #
class DedicatedAccountError(RuntimeError):
    """Raised when any dedicated-account operation fails."""


# --------------------------------------------------------------------------- #
#                            Wallet / Account DTOs                            #
# --------------------------------------------------------------------------- #
class DedicatedAccount:
    """Simple in-memory representation of a reserved account."""

    def __init__(
        self,
        account_reference: str,
        account_name: str,
        customer_email: str,
        contract_code: str,
        account_number: str,
        bank_name: str,
        bank_code: str,
        bvn: str | None = None,
        nin: str | None = None,
    ):
        self.account_reference = account_reference
        self.account_name = account_name
        self.customer_email = customer_email
        self.contract_code = contract_code
        self.account_number = account_number
        self.bank_name = bank_name
        self.bank_code = bank_code
        self.bvn = bvn
        self.nin = nin

    def to_dict(self) -> Dict:
        return self.__dict__

    @classmethod
    def from_dict(cls, data: Dict) -> "DedicatedAccount":
        return cls(**data)


class Wallet:
    """Thin wallet abstraction (Monnify wallet that funds withdrawals)."""

    def __init__(
        self,
        account_number: str,
        available_balance: float,
        ledger_balance: float,
    ):
        self.account_number = account_number
        self.available_balance = available_balance
        self.ledger_balance = ledger_balance


# --------------------------------------------------------------------------- #
#                          DedicatedAccountService                            #
# --------------------------------------------------------------------------- #
class DedicatedAccountService:
    """
    High-level facade around Monnify reserved-account operations.
    """

    def __init__(self, api_key: str, secret: str, sandbox: bool = True):
        self._client = Monnify(api_key, secret, sandbox)
        self._token: str | None = None

    # ------------- #
    #   INTERNAL    #
    # ------------- #

    def _handle_response(self, resp: Dict):
        """Checks Monnify response for failure and raises DedicatedAccountError."""
        if resp.get("requestSuccessful") is False:
            # Monnify errors usually have a responseMessage and responseCode
            error_code = resp.get("responseCode", "500")
            error_msg = resp.get("responseMessage", "Unknown Monnify API error")
            raise DedicatedAccountError(f"Monnify API Failure [{error_code}]: {error_msg}")
        return resp["responseBody"] # Return the success body
    
    def _ensure_token(self) -> str:
        if not self._token:
            resp = self._client.auth_login()
            self._token = resp["responseBody"]["accessToken"]
        return self._token

    # ------------- #
    #   ACCOUNTS    #
    # ------------- #
    def create_account(
        self,
        *,
        account_name: str,
        customer_email: str,
        contract_code: str,
        bvn: str | None = None,
        nin: str | None = None,
        income_split_config: List[Dict] | None = None,
    ) -> DedicatedAccount:
        """
        Create a new reserved account.

        Returns
        -------
        DedicatedAccount instance with populated account_number & bank details.
        """
        account_ref = str(uuid.uuid4())
        logger.info(f"Creating dedicated account with reference: {account_ref}")
        token = self._ensure_token()
        logger.info(f"Obtained auth token for Monnify: {token[:10]}****")
        resp = self._client.reserved_account_create(
            token,
            account_reference=account_ref,
            account_name=account_name,
            customer_email=customer_email,
            contract_code=contract_code,
            bvn=bvn,
            nin=nin,
            income_split_config=income_split_config,
        )
        try:
            body = self._handle_response(resp)
        except DedicatedAccountError as e:
            logger.error(f"Dedicated account creation failed for {customer_email}: {e}")
            raise
        logger.info(f"Dedicated account created successfully: {body}")
        bank = body["accounts"][0]  # Monnify always returns ≥1 bank
        return DedicatedAccount(
            account_reference=account_ref,
            account_name=account_name,
            customer_email=customer_email,
            contract_code=contract_code,
            account_number=bank["accountNumber"],
            bank_name=bank["bankName"],
            bank_code=bank["bankCode"],
            bvn=bvn,
            nin=nin,
        )

    def get_account(self, account_reference: str) -> DedicatedAccount:
        """
        Fetch account details from Monnify.
        """
        token = self._ensure_token()
        resp = self._client.reserved_account_details(token, account_reference=account_reference)
        body = self._handle_response(resp)
        bank = body["accounts"][0]
        return DedicatedAccount(
            account_reference=account_reference,
            account_name=body["accountName"],
            customer_email=body["customerEmail"],
            contract_code=body["contractCode"],
            account_number=bank["accountNumber"],
            bank_name=bank["bankName"],
            bank_code=bank["bankCode"],
        )
    
    
    # ------------- #
    #   DEPOSITS    #
    # ------------- #
    def deposit_webhook(self, payload: Dict) -> Dict:
        """
        Validate and parse a Monnify webhook payload.

        Example payload (trimmed):
        {
          "eventType": "SUCCESSFUL_TRANSACTION",
          "eventData": {
              "paymentReference": "...",
              "amountPaid": 1000,
              "accountNumber": "5000123456"
          }
        }

        Returns
        -------
        Dict with keys: account_number, amount, payment_reference, paid_at
        """
        if payload.get("eventType") != "SUCCESSFUL_TRANSACTION":
            raise DedicatedAccountError("Unsupported webhook event")

        data = payload["eventData"]
        return {
            "account_number": data["accountNumber"],
            "amount": float(data["amountPaid"]),
            "payment_reference": data["paymentReference"],
            "paid_at": data.get("paidOn", _dt.datetime.utcnow().isoformat()),
        }

    # ------------- #
    #   WITHDRAWAL  #
    # ------------- #
    def withdraw(
        self,
        *,
        source_account: str,
        destination_account: str,
        destination_bank_code: str,
        amount: float,
        narration: str = "Withdrawal from dedicated account",
    ) -> str:
        """
        Withdraw money **from** the wallet account (source_account)
        **to** the external bank account (destination_account).

        Returns
        -------
        Monnify transaction reference (str)
        """
        token = self._ensure_token()
        reference = str(uuid.uuid4())
        resp = self._client.disburse_single(
            token,
            amount=amount,
            reference=reference,
            narration=narration,
            destination_bank_code=destination_bank_code,
            destination_account_number=destination_account,
            source_account_number=source_account,
        )
        return resp["responseBody"]["transactionReference"]

    # ------------- #
    #   WALLET      #
    # ------------- #
    def wallet_balance(self, wallet_account: str) -> Wallet:
        """
        Get real-time balance of the Monnify **wallet account**.
        (This is *not* the reserved account balance – Monnify doesn’t expose it.)
        """
        token = self._ensure_token()
        resp = self._client.wallet_balance(token, account_number=wallet_account)
        body = self._handle_response(resp)
        return Wallet(
            account_number=wallet_account,
            available_balance=body["availableBalance"],
            ledger_balance=body["ledgerBalance"],
        )

    # ------------- #
    #   HISTORY     #
    # ------------- #
    def transactions(
        self,
        account_reference: str,
        *,
        page: int = 0,
        size: int = 10,
    ) -> List[Dict]:
        """
        Get paginated list of deposits made **into** the reserved account.
        Each Dict contains:
        - transaction_reference
        - amount
        - payment_reference
        - payment_status
        - paid_on
        """
        token = self._ensure_token()
        resp = self._client.reserved_account_transactions(
            token,
            account_reference=account_reference,
            page=page,
            size=size,
        )
        content = resp["responseBody"]["content"]
        return [
            {
                "transaction_reference": tx["transactionReference"],
                "amount": tx["amount"],
                "payment_reference": tx["paymentReference"],
                "payment_status": tx["paymentStatus"],
                "paid_on": tx["completedOn"],
            }
            for tx in content
        ]
    
    def transaction_status(self, transaction_reference: str) -> Dict:
        """
        Get the status of a specific transaction by its reference.

        Returns
        -------
        Dict with keys: transaction_reference, amount, payment_reference, payment_status, paid_on
        """
        token = self._ensure_token()
        resp = self._client.transaction_status(
            token,
            transaction_reference=transaction_reference,
        )
        body = self._handle_response(resp)
        return {
            "transaction_reference": body["transactionReference"],
            "amount": body["amount"],
            "payment_reference": body["paymentReference"],
            "payment_status": body["paymentStatus"],
            "paid_on": body["completedOn"],
        }
    
    # ------------- #
    #   UPDATE BVN  #
    # ------------- #
    def update_bvn_on_reserved_account(
        self,
        *,
        account_reference: str,
        bvn: str,
    ) -> None:
        """
        Link/overwrite the BVN on an existing Monnify reserved account.

        Parameters
        ----------
        account_reference : str
            The unique account reference returned when the account was created.
        bvn : str
            The 11-digit Bank Verification Number to link.

        Raises
        ------
        DedicatedAccountError
            If the API call fails.
        """
        if len(str(bvn)) != 11:
            raise DedicatedAccountError("BVN must be exactly 11 digits.")

        token = self._ensure_token()
        try:
            resp = self._client.reserved_account_update_bvn(
                token,
                account_reference=account_reference,
                bvn=bvn,
            )
            # Check for Monnify API errors after the call
            self._handle_response(resp)
        except Exception as exc:
            raise DedicatedAccountError(f"Failed to update BVN: {exc}")
        
    def fetch_banks(self) -> List[Dict]:
        """
        Fetch the list of banks supported by Monnify.

        Returns
        -------
        List of Dicts with keys: name, code
        """
        token = self._ensure_token()
        resp = self._client.bank(token)
        banks = resp["responseBody"]
        return [{"name": bank["name"], "code": bank["code"]} for bank in banks]
    
    def validate_account(self, account_number: str, bank_code: str) -> Dict:
        """
        Validate a bank account number with the given bank code.

        Parameters
        ----------
        account_number : str
            The bank account number to validate.
        bank_code : str
            The bank code corresponding to the bank.

        Returns
        -------
        Dict with keys: account_name, account_number, bank_code
        """
        token = self._ensure_token()
        resp = self._client.validate_account(token, account_number=account_number, bank_code=bank_code)
        body = self._handle_response(resp)
        return {
            "account_name": body["accountName"],
            "account_number": body["accountNumber"],
            "bank_code": body["bankCode"],
        }


# --------------------------------------------------------------------------- #
#                               USAGE EXAMPLE                                 #
# --------------------------------------------------------------------------- #
# if __name__ == "__main__":
#     import os

#     svc = DedicatedAccountService(
#         api_key=os.getenv("MONNIFY_API_KEY"),
#         secret=os.getenv("MONNIFY_SECRET_KEY"),
#         sandbox=True,
#     )

#     # 1. Create account
#     acc = svc.create_account(
#         account_name="Ada Lovelace",
#         customer_email="ada@example.com",
#         customer_name="Ada Lovelace",
#         contract_code="100693167467",
#         bvn="21212121212",
#     )
#     print("Created =>", acc.to_dict())

#     # 2. Wallet balance (the pool that funds withdrawals)
#     wallet = svc.wallet_balance("3934178936")
#     print("Wallet balance =>", wallet.available_balance)

#     # 3. Withdraw ₦1 000 from wallet → external GTBank account
#     tx_ref = svc.withdraw(
#         source_account=wallet.account_number,
#         destination_account="0111946768",
#         destination_bank_code="058",
#         amount=1000,
#     )
#     print("Withdrawal reference =>", tx_ref)

#     # 4. Deposit history (webhook already processed)
#     txs = svc.transactions(acc.account_reference)
#     print("Transactions =>", txs)
