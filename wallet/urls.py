from django.urls import path, include
from rest_framework.routers import DefaultRouter

# Import your APIView classes (for specific custom endpoints if not covered by ViewSets)
from .views import (
    WalletDetailsView,
    AllTransactionsView,
    WithdrawalRequestView,
    TransactionDetailView,
    MonnifyWebhookView,
)

# Import your ViewSet classes
from .viewsets import (
    WalletViewSet,
    TransactionViewSet,
    WithdrawalViewSet,
    BankViewSet,
)

# Create a router instance
router = DefaultRouter()

# Register your ViewSets with the router.
# The `basename` argument is important for reverse lookups, especially if queryset
# doesn't directly provide a model. It's good practice to always provide it.
router.register(r'wallets', WalletViewSet, basename='wallet') # Changed to 'wallets' for plural, standard REST
router.register(r'transactions', TransactionViewSet, basename='transaction')
router.register(r'withdrawals', WithdrawalViewSet, basename='withdrawal')
router.register(r'banks', BankViewSet, basename='bank')

# Define your URL patterns
urlpatterns = [
    # Include the router URLs under a 'api/' prefix.
    # This will generate paths like:
    # /api/wallets/
    # /api/wallets/<id>/
    # /api/transactions/
    # /api/transactions/<id>/
    # /api/withdrawals/
    # /api/withdrawals/<id>/
    path('api/', include(router.urls)),

    # Custom APIView paths if they offer functionality *not* covered by the ViewSets.
    # Review these carefully to avoid redundancy.

    # 1. Wallet Details:
    # WalletViewSet already has a 'my_wallet' action at /api/wallets/my-wallet/
    # It's better to use the ViewSet's custom action for wallet details,
    # as it also handles DVA creation logic.
    # So, we can remove the root path unless you have a strong reason for it.
    path('', WalletDetailsView.as_view(), name='wallet-details'), # Consider removing this if /api/wallets/my-wallet/ is preferred

    # 2. All Transactions:
    # TransactionViewSet provides /api/transactions/ for listing all transactions
    # (filtered by user due to get_queryset() in the ViewSet).
    # So, AllTransactionsView is redundant.
    path('transactions/', AllTransactionsView.as_view(), name='all-transactions'), # REMOVE THIS

    # 3. Transaction Detail:
    # TransactionViewSet already provides /api/transactions/<id>/ for retrieving a single transaction.
    # The 'pk' parameter in ViewSet methods handles this.
    # So, TransactionDetailView is redundant.
    path('transactions/<int:transaction_id>/', TransactionDetailView.as_view(), name='transaction-detail'), # REMOVE THIS

    # 4. Withdrawal Request:
    # WithdrawalViewSet already has a 'create' method handled by the router at /api/withdrawals/
    # So, WithdrawalRequestView is redundant.
    path('withdraw/', WithdrawalRequestView.as_view(), name='withdraw'), # REMOVE THIS

    # --- Paystack Webhook Endpoint (CRITICAL!) ---
    # This is where Paystack will send notifications for deposit successes, transfer failures, etc.
    # This MUST be csrf_exempt. Ensure it's not authenticated with TokenAuthentication.
    # from .views import PaystackWebhookView # Assuming you create this view
    path('webhook/monnify/', MonnifyWebhookView.as_view(), name='monnify-webhook'),

    # If you still want a direct endpoint for authenticated user's wallet summary (e.g., /my-wallet/)
    # and prefer it separate from the ViewSet's /api/wallets/my-wallet/, keep this:
    path('my-wallet/', WalletDetailsView.as_view(), name='my-wallet-summary'),
]