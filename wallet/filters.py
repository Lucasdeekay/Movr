# payments/filters.py
import django_filters
from .models import Wallet, Transaction, Withdrawal


class WalletFilter(django_filters.FilterSet):
    # This filter is for admin use, as user's can only see their own wallet.
    # For admin, you might want to filter by user's email, etc.
    user_email = django_filters.CharFilter(field_name='user__email', lookup_expr='icontains')
    balance_gt = django_filters.NumberFilter(field_name='balance', lookup_expr='gt')
    balance_lt = django_filters.NumberFilter(field_name='balance', lookup_expr='lt')

    class Meta:
        model = Wallet
        fields = ['user_email', 'balance_gt', 'balance_lt', 'paystack_customer_code', 'dva_account_number', 'dva_bank_name']


class TransactionFilter(django_filters.FilterSet):
    # For user's own transactions, filters like type, status, and date range are useful.
    transaction_type = django_filters.CharFilter(lookup_expr='iexact') # Case-insensitive exact match
    status = django_filters.CharFilter(lookup_expr='iexact')
    min_amount = django_filters.NumberFilter(field_name='amount', lookup_expr='gte')
    max_amount = django_filters.NumberFilter(field_name='amount', lookup_expr='lte')
    start_date = django_filters.DateFilter(field_name='created_at', lookup_expr='gte')
    end_date = django_filters.DateFilter(field_name='created_at', lookup_expr='lte')

    class Meta:
        model = Transaction
        fields = ['transaction_type', 'status', 'min_amount', 'max_amount', 'start_date', 'end_date']


class WithdrawalFilter(django_filters.FilterSet):
    # For user's own withdrawals, status and date are common filters.
    status = django_filters.CharFilter(lookup_expr='iexact')
    min_amount = django_filters.NumberFilter(field_name='amount', lookup_expr='gte')
    max_amount = django_filters.NumberFilter(field_name='amount', lookup_expr='lte')
    start_date = django_filters.DateFilter(field_name='created_at', lookup_expr='gte')
    end_date = django_filters.DateFilter(field_name='created_at', lookup_expr='lte')

    class Meta:
        model = Withdrawal
        fields = ['status', 'min_amount', 'max_amount', 'start_date', 'end_date']