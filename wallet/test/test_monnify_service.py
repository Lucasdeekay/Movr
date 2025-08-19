"""
pytest -q tests/test_monnify_service.py
"""
import pytest
import responses
from monnify_service import DedicatedAccountService, DedicatedAccount

API_KEY = "MK_TEST_123456"
SECRET = "test-secret"


@pytest.fixture
def svc() -> DedicatedAccountService:
    return DedicatedAccountService(API_KEY, SECRET, sandbox=True)


@responses.activate
def test_create_account(svc: DedicatedAccountService):
    """Happy path for account creation"""
    responses.add(
        responses.POST,
        "https://sandbox.monnify.com/api/v1/auth/login",
        json={
            "requestSuccessful": True,
            "responseCode": "0",
            "responseBody": {"accessToken": "token123", "expiresIn": 3600},
        },
    )
    responses.add(
        responses.POST,
        "https://sandbox.monnify.com/api/v2/bank-transfer/reserved-accounts",
        json={
            "requestSuccessful": True,
            "responseCode": "0",
            "responseBody": {
                "accountReference": "uuid-123",
                "accounts": [
                    {
                        "accountNumber": "5000999999",
                        "bankName": "Moniepoint Microfinance Bank",
                        "bankCode": "50515",
                    }
                ],
            },
        },
    )

    acc = svc.create_account(
        account_name="Ada Lovelace",
        customer_email="ada@example.com",
        customer_name="Ada Lovelace",
        contract_code="100693167467",
        bvn="21212121212",
    )
    assert acc.account_number == "5000999999"
    assert acc.account_reference == "uuid-123"


@responses.activate
def test_withdraw(svc: DedicatedAccountService):
    """Withdrawal happy path"""
    responses.add(
        responses.POST,
        "https://sandbox.monnify.com/api/v1/auth/login",
        json={
            "requestSuccessful": True,
            "responseCode": "0",
            "responseBody": {"accessToken": "token123"},
        },
    )
    responses.add(
        responses.POST,
        "https://sandbox.monnify.com/api/v2/disbursements/single",
        json={
            "requestSuccessful": True,
            "responseCode": "0",
            "responseBody": {"transactionReference": "MFDS2024WITHDRAW"},
        },
    )

    tx_ref = svc.withdraw(
        source_account="3934178936",
        destination_account="2085886393",
        destination_bank_code="057",
        amount=1000,
        narration="Test withdrawal",
    )
    assert tx_ref == "MFDS2024WITHDRAW"


@responses.activate
def test_wallet_balance(svc: DedicatedAccountService):
    responses.add(
        responses.POST,
        "https://sandbox.monnify.com/api/v1/auth/login",
        json={
            "requestSuccessful": True,
            "responseCode": "0",
            "responseBody": {"accessToken": "token123"},
        },
    )
    responses.add(
        responses.GET,
        "https://sandbox.monnify.com/api/v2/disbursements/wallet-balance",
        json={
            "requestSuccessful": True,
            "responseCode": "0",
            "responseBody": {"availableBalance": 5000.0, "ledgerBalance": 5000.0},
        },
    )

    wallet = svc.wallet_balance("3934178936")
    assert wallet.available_balance == 5000.0


def test_deposit_webhook():
    """Webhook parsing test (no HTTP)"""
    svc = DedicatedAccountService(API_KEY, SECRET)
    payload = {
        "eventType": "SUCCESSFUL_TRANSACTION",
        "eventData": {
            "paymentReference": "pay-ref-001",
            "amountPaid": 1000,
            "accountNumber": "5000123456",
            "paidOn": "2024-08-16T12:00:00",
        },
    }
    parsed = svc.deposit_webhook(payload)
    assert parsed["amount"] == 1000
    assert parsed["account_number"] == "5000123456"