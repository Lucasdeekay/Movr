# Paystack DVA Integration for Movr

This document outlines the integration of Paystack Direct Virtual Account (DVA) for handling deposits and withdrawals in the Movr application.

## Overview

The integration provides:
- **Direct Virtual Account (DVA) creation** for users
- **Automated deposit processing** via Paystack
- **Secure withdrawal handling** to Nigerian bank accounts
- **Webhook processing** for real-time transaction updates
- **Transaction tracking** and history

## New Models

### PaystackAccount
Stores user's Paystack DVA account information:
- `user`: OneToOne relationship with CustomUser
- `account_type`: DVA or Standard account
- `account_number`: Virtual account number
- `bank_name`: Associated bank name
- `bank_code`: Bank code
- `paystack_customer_code`: Paystack customer identifier
- `paystack_account_id`: Paystack account identifier
- `status`: Account status (active, inactive, pending, suspended)
- `is_active`: Boolean flag for active accounts

### PaystackTransaction
Tracks all Paystack-related transactions:
- `user`: ForeignKey to CustomUser
- `transaction_type`: Deposit, Withdrawal, or Transfer
- `paystack_reference`: Unique transaction reference
- `paystack_transaction_id`: Paystack transaction ID
- `amount`: Transaction amount
- `currency`: Transaction currency (default: NGN)
- `status`: Transaction status (pending, success, failed, abandoned, reversed)
- `gateway_response`: Response from Paystack
- `channel`: Payment channel used
- `ip_address`: IP address of transaction
- `narration`: Transaction description
- `fees`: Transaction fees
- `paid_at`: Payment timestamp

## API Endpoints

### 1. Paystack Account Management
```
GET /api/paystack/account/ - Get user's Paystack account details
POST /api/paystack/account/ - Create new Paystack DVA account
```

### 2. Deposits
```
POST /api/paystack/deposit/ - Initiate a Paystack deposit
```

**Request Body:**
```json
{
    "amount": "1000.00",
    "email": "user@example.com",
    "reference": "optional_reference",
    "callback_url": "optional_callback_url"
}
```

**Response:**
```json
{
    "message": "Deposit initiated successfully",
    "authorization_url": "https://checkout.paystack.com/...",
    "reference": "DEP_123_abc123",
    "transaction_id": 1
}
```

### 3. Withdrawals
```
POST /api/paystack/withdraw/ - Initiate a Paystack withdrawal
```

**Request Body:**
```json
{
    "amount": "500.00",
    "bank_code": "044",
    "account_number": "1234567890",
    "account_name": "John Doe",
    "narration": "Withdrawal to bank account"
}
```

**Response:**
```json
{
    "message": "Withdrawal initiated successfully",
    "reference": "WTH_123_abc123",
    "transaction_id": 2
}
```

### 4. Bank Information
```
GET /api/paystack/banks/ - Get list of available banks
POST /api/paystack/resolve-account/ - Resolve account number
```

### 5. Transaction History
```
GET /api/paystack/transactions/ - Get user's Paystack transactions
```

### 6. Webhook
```
POST /api/paystack/webhook/ - Paystack webhook endpoint
```

## Configuration

Add the following environment variables to your `.env` file:

```env
# Paystack Configuration
PAYSTACK_SECRET_KEY=sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
PAYSTACK_PUBLIC_KEY=pk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
PAYSTACK_SUBACCOUNT_CODE=ACCT_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
PAYSTACK_SPLIT_CODE=SPLT_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
PAYSTACK_WEBHOOK_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Usage Examples

### Creating a DVA Account
```python
from Api.paystack_service import paystack_service

# Create DVA account for user
success, response = paystack_service.create_dva_account(
    user=user,
    preferred_bank="044"  # Optional: preferred bank code
)

if success:
    account = PaystackAccount.objects.get(user=user)
    print(f"Account created: {account.account_number}")
```

### Processing Deposits
```python
# User makes payment to their DVA account
# Paystack sends webhook to /api/paystack/webhook/
# System automatically updates wallet balance
```

### Processing Withdrawals
```python
# User initiates withdrawal
success, response = paystack_service.initiate_transfer(
    recipient_code="RCP_xxxxxxxxx",
    amount=Decimal("1000.00"),
    reason="Withdrawal to bank account"
)
```

## Webhook Events

The system handles the following Paystack webhook events:

1. **charge.success** - Successful deposit
2. **transfer.success** - Successful withdrawal
3. **transfer.failed** - Failed withdrawal

## Security Features

- **Webhook signature verification** using HMAC SHA512
- **Transaction reference validation**
- **Atomic database operations** for wallet updates
- **Comprehensive error handling** and logging

## Error Handling

The integration includes robust error handling for:
- Invalid Paystack responses
- Network failures
- Database transaction failures
- Insufficient wallet balance
- Invalid account details

## Testing

To test the integration:

1. Use Paystack test keys
2. Create test DVA accounts
3. Simulate deposits and withdrawals
4. Test webhook processing

## Dependencies

- `paystack==2.0.0` - Paystack Python SDK
- `requests` - HTTP requests
- `hmac` - Webhook signature verification

## Migration

Run the following commands to apply database changes:

```bash
python manage.py makemigrations
python manage.py migrate
```

## Admin Interface

The Paystack models are registered in Django admin:
- **PaystackAccountAdmin** - Manage user accounts
- **PaystackTransactionAdmin** - View transaction history

## Notes

- All amounts are stored in Naira (NGN)
- Paystack amounts are in kobo (1 NGN = 100 kobo)
- Webhook processing is automatic and secure
- Transaction history is maintained for audit purposes
- Failed transactions are logged with detailed error messages 