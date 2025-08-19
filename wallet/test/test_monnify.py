"""
pytest -q tests/test_monnify.py
"""
import os
import pytest
import responses

from monnify import Monnify, MonnifyError

API_KEY = "MK_TEST_123456"
SECRET = "test-secret"
SANDBOX = True


@pytest.fixture
def client() -> Monnify:
    return Monnify(API_KEY, SECRET, sandbox=SANDBOX)


@responses.activate
def test_auth_login(client: Monnify):
    """Happy path for /api/v1/auth/login"""
    responses.add(
        responses.POST,
        "https://sandbox.monnify.com/api/v1/auth/login",
        json={
            "requestSuccessful": True,
            "responseMessage": "success",
            "responseCode": "0",
            "responseBody": {
                "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                "expiresIn": 3600,
            },
        },
        status=200,
    )
    resp = client.auth_login()
    assert resp["responseBody"]["accessToken"]


@responses.activate
def test_auth_login_error(client: Monnify):
    """Login with wrong credentials should raise MonnifyError"""
    responses.add(
        responses.POST,
        "https://sandbox.monnify.com/api/v1/auth/login",
        json={
            "requestSuccessful": False,
            "responseMessage": "Invalid credentials",
            "responseCode": "99",
        },
        status=200,
    )
    with pytest.raises(MonnifyError):
        client.auth_login()


@responses.activate
def test_transactions_init(client: Monnify):
    """Test init-transaction endpoint"""
    responses.add(
        responses.POST,
        "https://sandbox.monnify.com/api/v1/merchant/transactions/init-transaction",
        json={
            "requestSuccessful": True,
            "responseMessage": "success",
            "responseCode": "0",
            "responseBody": {
                "transactionReference": "MNFY|2024|000001",
                "checkoutUrl": "https://checkout.monnify.com",
            },
        },
        status=200,
    )
    token = "fake-token"
    resp = client.transactions_init(
        token,
        amount=100,
        customer_email="test@example.com",
        payment_reference="pytest-001",
        currency_code="NGN",
    )
    assert resp["responseBody"]["transactionReference"]


@responses.activate
def test_reserved_account_create(client: Monnify):
    """Test reserved account creation"""
    responses.add(
        responses.POST,
        "https://sandbox.monnify.com/api/v2/bank-transfer/reserved-accounts",
        json={
            "requestSuccessful": True,
            "responseCode": "0",
            "responseBody": {
                "accountReference": "pytest-uuid",
                "accounts": [
                    {
                        "accountNumber": "5000123456",
                        "bankName": "Moniepoint Microfinance Bank",
                        "bankCode": "50515",
                    }
                ],
            },
        },
        status=200,
    )
    token = "fake-token"
    resp = client.reserved_account_create(
        token,
        account_reference="pytest-uuid",
        account_name="Test User",
        customer_email="test@example.com",
        contract_code="100693167467",
    )
    assert resp["responseBody"]["accounts"][0]["accountNumber"] == "5000123456"


@responses.activate
def test_disburse_single(client: Monnify):
    """Test single disbursement"""
    responses.add(
        responses.POST,
        "https://sandbox.monnify.com/api/v2/disbursements/single",
        json={
            "requestSuccessful": True,
            "responseCode": "0",
            "responseBody": {
                "transactionReference": "MFDS2024TEST",
                "status": "SUCCESS",
            },
        },
        status=200,
    )
    token = "fake-token"
    resp = client.disburse_single(
        token,
        amount=500,
        reference="pytest-withdraw",
        narration="Test withdrawal",
        destination_bank_code="058",
        destination_account_number="2085886393",
        source_account_number="3934178936",
    )
    assert resp["responseBody"]["transactionReference"] == "MFDS2024TEST"