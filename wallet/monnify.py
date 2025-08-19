"""
Monnify Python SDK
==================

A minimal, self-contained Python client for the Monnify REST API.
It supports **all endpoints** documented in the reference guide
(Authentication, Transactions, Disbursements, Reserved Accounts, …).

The client is intentionally **stateless**: every method returns the raw
JSON-decoded response from the server.  The caller is responsible for
handling errors and data validation.

Author : PappyCoder
Date   : 2024-08-16
"""

import base64
import datetime as _dt
import os
import typing as _t
import urllib.parse as _urlparse

import requests
from requests import Response


# ------------------------- #
#   Exceptions & Helpers    #
# ------------------------- #
class MonnifyError(RuntimeError):
    """Raised when the server returns a non-zero responseCode."""
    pass


def _b64(s: str) -> str:
    """Return base-64 encoded string."""
    return base64.b64encode(s.encode()).decode()


def _today() -> str:
    """Return today’s date in YYYY-MM-DD HH:MM:SS format."""
    return _dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def _raise_on_error(data: dict):
    """Raise MonnifyError if responseCode != 0."""
    if data.get("responseCode") != "0":
        raise MonnifyError(f"{data.get('responseMessage')} ({data.get('responseCode')})")


# ------------------------- #
#          Client           #
# ------------------------- #
class Monnify:
    """
    A thin wrapper around the Monnify REST API.

    Usage
    -----
    >>> from monnify import Monnify
    >>> api = Monnify(api_key="MK_TEST_…", secret="…", sandbox=True)
    >>> token = api.auth_login()["responseBody"]["accessToken"]
    >>> txns = api.transactions_search(page=0, size=10)
    """

    # ------------- #
    #   Constants   #
    # ------------- #
    SANDBOX_URL = "https://sandbox.monnify.com"
    LIVE_URL = "https://api.monnify.com"

    # ------------- #
    #   Init        #
    # ------------- #
    def __init__(
        self,
        api_key: str,
        secret: str,
        sandbox: bool = True,
        timeout: int = 30,
        session: requests.Session | None = None,
    ):
        self._base_url = self.SANDBOX_URL if sandbox else self.LIVE_URL
        self._api_key = api_key
        self._secret = secret
        self._timeout = timeout
        self._session = session or requests.Session()

    # ------------- #
    #   Internal    #
    # ------------- #
    def _auth_header(self) -> dict[str, str]:
        """Return Basic auth header for login endpoint."""
        basic = _b64(f"{self._api_key}:{self._secret}")
        return {"Authorization": f"Basic {basic}"}

    def _bearer_header(self, token: str) -> dict[str, str]:
        """Return Bearer auth header."""
        return {"Authorization": f"Bearer {token}"}

    def _request(
        self,
        method: str,
        endpoint: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        json: dict | list | None = None,
        data: dict | None = None,
    ) -> dict:
        """Generic HTTP helper."""
        url = f"{self._base_url}{endpoint}"
        resp: Response = self._session.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json,
            data=data,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        _raise_on_error(data)
        return data

    # ========================= #
    #  AUTHENTICATION           #
    # ========================= #
    def auth_login(self) -> dict:
        """
        POST /api/v1/auth/login
        Returns
        -------
        {
          "requestSuccessful": true,
          "responseMessage": "success",
          "responseCode": "0",
          "responseBody": {
              "accessToken": "eyJhbGci...",
              "expiresIn": 3567
          }
        }
        """
        return self._request(
            "POST",
            "/api/v1/auth/login",
            headers=self._auth_header(),
            json={},
        )

    # ========================= #
    #  TRANSACTIONS             #
    # ========================= #
    def transactions_init(
        self,
        token: str,
        *,
        amount: float,
        customer_email: str,
        payment_reference: str,
        currency_code: str = "NGN",
        customer_name: str | None = None,
        payment_description: str | None = None,
        contract_code: str | None = None,
        redirect_url: str | None = None,
        payment_methods: list[str] | None = None,
        income_split_config: list[dict] | None = None,
        meta_data: dict | None = None,
    ) -> dict:
        """
        POST /api/v1/merchant/transactions/init-transaction
        """
        body = {
            "amount": amount,
            "customerEmail": customer_email,
            "paymentReference": payment_reference,
            "currencyCode": currency_code,
            "customerName": customer_name,
            "paymentDescription": payment_description,
            "contractCode": contract_code,
            "redirectUrl": redirect_url,
            "paymentMethods": payment_methods,
            "incomeSplitConfig": income_split_config,
            "metaData": meta_data,
        }
        return self._request(
            "POST",
            "/api/v1/merchant/transactions/init-transaction",
            headers=self._bearer_header(token),
            json={k: v for k, v in body.items() if v is not None},
        )

    def transactions_search(
        self,
        token: str,
        *,
        page: int = 0,
        size: int = 10,
        payment_reference: str | None = None,
        transaction_reference: str | None = None,
        from_amount: float | None = None,
        to_amount: float | None = None,
        amount: float | None = None,
        customer_name: str | None = None,
        customer_email: str | None = None,
        payment_status: str | None = None,
        from_ts: int | None = None,
        to_ts: int | None = None,
    ) -> dict:
        """
        GET /api/v1/transactions/search
        """
        params = {
            "page": page,
            "size": size,
            "paymentReference": payment_reference,
            "transactionReference": transaction_reference,
            "fromAmount": from_amount,
            "toAmount": to_amount,
            "amount": amount,
            "customerName": customer_name,
            "customerEmail": customer_email,
            "paymentStatus": payment_status,
            "from": from_ts,
            "to": to_ts,
        }
        return self._request(
            "GET",
            "/api/v1/transactions/search",
            headers=self._bearer_header(token),
            params={k: v for k, v in params.items() if v is not None},
        )

    def transaction_status(self, token: str, *, transaction_reference: str) -> dict:
        """
        GET /api/v2/transactions/{transaction_reference}
        """
        ref = _urlparse.quote(transaction_reference)
        return self._request(
            "GET",
            f"/api/v2/transactions/{ref}",
            headers=self._bearer_header(token),
        )

    # ========================= #
    #  DISBURSEMENTS            #
    # ========================= #
    def disburse_single(
        self,
        token: str,
        *,
        amount: float,
        reference: str,
        narration: str,
        destination_bank_code: str,
        destination_account_number: str,
        source_account_number: str,
        currency: str = "NGN",
        async_: bool = False,
    ) -> dict:
        """
        POST /api/v2/disbursements/single
        """
        body = {
            "amount": amount,
            "reference": reference,
            "narration": narration,
            "destinationBankCode": destination_bank_code,
            "destinationAccountNumber": destination_account_number,
            "currency": currency,
            "sourceAccountNumber": source_account_number,
            "async": async_,
        }
        return self._request(
            "POST",
            "/api/v2/disbursements/single",
            headers=self._bearer_header(token),
            json={k: v for k, v in body.items() if v is not None},
        )

    def disburse_bulk(
        self,
        token: str,
        *,
        batch_reference: str,
        title: str,
        narration: str,
        source_account_number: str,
        on_validation_failure: str = "CONTINUE",
        notification_interval: int = 25,
        transaction_list: list[dict],
    ) -> dict:
        """
        POST /api/v2/disbursements/batch
        """
        body = {
            "batchReference": batch_reference,
            "title": title,
            "narration": narration,
            "sourceAccountNumber": source_account_number,
            "onValidationFailure": on_validation_failure,
            "notificationInterval": notification_interval,
            "transactionList": transaction_list,
        }
        return self._request(
            "POST",
            "/api/v2/disbursements/batch",
            headers=self._bearer_header(token),
            json=body,
        )

    def disburse_validate_otp(
        self, token: str, *, reference: str, authorization_code: str
    ) -> dict:
        """
        POST /api/v2/disbursements/single/validate-otp
        """
        body = {"reference": reference, "authorizationCode": authorization_code}
        return self._request(
            "POST",
            "/api/v2/disbursements/single/validate-otp",
            headers=self._bearer_header(token),
            json=body,
        )

    def disburse_bulk_validate_otp(
        self, token: str, *, reference: str, authorization_code: str
    ) -> dict:
        """
        POST /api/v2/disbursements/batch/validate-otp
        """
        body = {"reference": reference, "authorizationCode": authorization_code}
        return self._request(
            "POST",
            "/api/v2/disbursements/batch/validate-otp",
            headers=self._bearer_header(token),
            json=body,
        )

    def disburse_single_status(self, token: str, *, reference: str) -> dict:
        """
        GET /api/v2/disbursements/single/summary
        """
        return self._request(
            "GET",
            "/api/v2/disbursements/single/summary",
            headers=self._bearer_header(token),
            params={"reference": reference},
        )

    def wallet_balance(self, token: str, *, account_number: str) -> dict:
        """
        GET /api/v2/disbursements/wallet-balance
        """
        return self._request(
            "GET",
            "/api/v2/disbursements/wallet-balance",
            headers=self._bearer_header(token),
            params={"accountNumber": account_number},
        )

    # ========================= #
    #  RESERVED ACCOUNTS        #
    # ========================= #
    def reserved_account_create(
        self,
        token: str,
        *,
        account_reference: str,
        account_name: str,
        customer_email: str,
        contract_code: str,
        currency_code: str = "NGN",
        bvn: str | None = None,
        nin: str | None = None,
        get_all_available_banks: bool = True,
        income_split_config: list[dict] | None = None,
        restrict_payment_source: bool = False,
        allowed_payment_source: dict | None = None,
    ) -> dict:
        """
        POST /api/v2/bank-transfer/reserved-accounts
        """
        body = {
            "accountReference": account_reference,
            "accountName": account_name,
            "currencyCode": currency_code,
            "contractCode": contract_code,
            "customerEmail": customer_email,
            "bvn": bvn,
            "nin": nin,
            "getAllAvailableBanks": get_all_available_banks,
            "incomeSplitConfig": income_split_config,
            "restrictPaymentSource": restrict_payment_source,
            "allowedPaymentSource": allowed_payment_source,
        }
        return self._request(
            "POST",
            "/api/v2/bank-transfer/reserved-accounts",
            headers=self._bearer_header(token),
            json={k: v for k, v in body.items() if v is not None},
        )

    def reserved_account_details(self, token: str, *, account_reference: str) -> dict:
        """
        GET /api/v2/bank-transfer/reserved-accounts/{account_reference}
        """
        ref = _urlparse.quote(account_reference)
        return self._request(
            "GET",
            f"/api/v2/bank-transfer/reserved-accounts/{ref}",
            headers=self._bearer_header(token),
        )

    def reserved_account_transactions(
        self,
        token: str,
        *,
        account_reference: str,
        page: int = 0,
        size: int = 10,
    ) -> dict:
        """
        GET /api/v1/bank-transfer/reserved-accounts/transactions
        """
        return self._request(
            "GET",
            "/api/v1/bank-transfer/reserved-accounts/transactions",
            headers=self._bearer_header(token),
            params={"accountReference": account_reference, "page": page, "size": size},
        )

    # ========================= #
    #  INVOICES                 #
    # ========================= #
    def invoice_create(
        self,
        token: str,
        *,
        amount: float,
        invoice_reference: str,
        description: str,
        customer_email: str,
        customer_name: str,
        contract_code: str,
        expiry_date: str,
        currency_code: str = "NGN",
        redirect_url: str | None = None,
        income_split_config: list[dict] | None = None,
    ) -> dict:
        """
        POST /api/v1/invoice/create
        """
        body = {
            "amount": amount,
            "invoiceReference": invoice_reference,
            "description": description,
            "customerEmail": customer_email,
            "customerName": customer_name,
            "contractCode": contract_code,
            "expiryDate": expiry_date,
            "currencyCode": currency_code,
            "redirectUrl": redirect_url,
            "incomeSplitConfig": income_split_config,
        }
        return self._request(
            "POST",
            "/api/v1/invoice/create",
            headers=self._bearer_header(token),
            json={k: v for k, v in body.items() if v is not None},
        )

    def invoice_details(self, token: str, *, invoice_reference: str) -> dict:
        """
        GET /api/v1/invoice/{invoice_reference}/details
        """
        ref = _urlparse.quote(invoice_reference)
        return self._request(
            "GET",
            f"/api/v1/invoice/{ref}/details",
            headers=self._bearer_header(token),
        )

    def invoice_all(
        self,
        token: str,
        page: int = 0,
        size: int = 10,
    ) -> dict:
        """
        GET /api/v1/invoice/all
        """
        return self._request(
            "GET",
            "/api/v1/invoice/all",
            headers=self._bearer_header(token),
            params={"page": page, "size": size},
        )

    def invoice_cancel(self, token: str, *, invoice_reference: str) -> dict:
        """
        DELETE /api/v1/invoice/{invoice_reference}/cancel
        """
        ref = _urlparse.quote(invoice_reference)
        return self._request(
            "DELETE",
            f"/api/v1/invoice/{ref}/cancel",
            headers=self._bearer_header(token),
            json={},
        )

    # ========================= #
    #  REFUNDS                  #
    # ========================= #
    def refund_initiate(
        self,
        token: str,
        *,
        transaction_reference: str,
        refund_reference: str,
        refund_amount: float,
        refund_reason: str,
        customer_note: str,
        destination_account_number: str | None = None,
        destination_bank_code: str | None = None,
    ) -> dict:
        """
        POST /api/v1/refunds/initiate-refund
        """
        body = {
            "transactionReference": transaction_reference,
            "refundReference": refund_reference,
            "refundAmount": refund_amount,
            "refundReason": refund_reason,
            "customerNote": customer_note,
            "destinationAccountNumber": destination_account_number,
            "destinationBankCode": destination_bank_code,
        }
        return self._request(
            "POST",
            "/api/v1/refunds/initiate-refund",
            headers=self._bearer_header(token),
            json={k: v for k, v in body.items() if v is not None},
        )

    def refund_status(self, token: str, *, refund_reference: str) -> dict:
        """
        GET /api/v1/refunds/{refund_reference}
        """
        return self._request(
            "GET",
            f"/api/v1/refunds/{refund_reference}",
            headers=self._bearer_header(token),
        )

    # ========================= #
    #  BANKS & UTILITIES        #
    # ========================= #
    def banks(self, token: str) -> dict:
        """
        GET /api/v1/banks
        """
        return self._request(
            "GET",
            "/api/v1/banks",
            headers=self._bearer_header(token),
        )

    def validate_account(
        self,
        token: str,
        *,
        account_number: str,
        bank_code: str,
    ) -> dict:
        """
        GET /api/v1/disbursements/account/validate
        """
        return self._request(
            "GET",
            "/api/v1/disbursements/account/validate",
            headers=self._bearer_header(token),
            params={"accountNumber": account_number, "bankCode": bank_code},
        )

    # ========================= #
    #  PAYCODES                 #
    # ========================= #
    def paycode_create(
        self,
        token: str,
        *,
        beneficiary_name: str,
        amount: float,
        paycode_reference: str,
        expiry_date: str,
        client_id: str,
    ) -> dict:
        """
        POST /api/v1/paycode
        """
        body = {
            "beneficiaryName": beneficiary_name,
            "amount": amount,
            "paycodeReference": paycode_reference,
            "expiryDate": expiry_date,
            "clientId": client_id,
        }
        return self._request(
            "POST",
            "/api/v1/paycode",
            headers=self._bearer_header(token),
            json=body,
        )

    def paycode_get(self, token: str, *, paycode_reference: str) -> dict:
        """
        GET /api/v1/paycode/{paycode_reference}
        """
        return self._request(
            "GET",
            f"/api/v1/paycode/{paycode_reference}",
            headers=self._bearer_header(token),
        )

    def paycode_clear(self, token: str, *, paycode_reference: str) -> dict:
        """
        GET /api/v1/paycode/{paycode_reference}/authorize
        """
        return self._request(
            "GET",
            f"/api/v1/paycode/{paycode_reference}/authorize",
            headers=self._bearer_header(token),
        )

    def paycode_delete(self, token: str, *, paycode_reference: str) -> dict:
        """
        DELETE /api/v1/paycode/{paycode_reference}
        """
        return self._request(
            "DELETE",
            f"/api/v1/paycode/{paycode_reference}",
            headers=self._bearer_header(token),
            json={},
        )
    
    def reserved_account_update_bvn(
        self,
        token: str,
        *,
        account_reference: str,
        bvn: str,
    ) -> dict:
        """
        Link/overwrite the BVN on an existing reserved account.
        """
        ref = _urlparse.quote(account_reference)
        return self._request(
            "PUT",
            f"/api/v1/bank-transfer/reserved-accounts/{ref}/kyc-info",
            headers=self._bearer_header(token),
            json={"bvn": bvn},
        )


# --------------------------------------------------------------------------- #
#                                 EXAMPLES                                    #
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    # Quick sanity test (requires env vars)
    api_key = os.getenv("MONNIFY_API_KEY")
    secret = os.getenv("MONNIFY_SECRET_KEY")
    if not (api_key and secret):
        raise SystemExit("Set MONNIFY_API_KEY & MONNIFY_SECRET_KEY env vars first!")

    api = Monnify(api_key, secret, sandbox=True)
    token = api.auth_login()["responseBody"]["accessToken"]

    # List banks
    banks = api.banks(token)
    print("Banks:", banks["responseBody"][:3])

    # Validate a test account
    resp = api.validate_account(token, account_number="2085886393", bank_code="057")
    print("Account validation:", resp)