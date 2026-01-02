from django.core.management.base import BaseCommand
from django.db import transaction as db_transaction
from django.utils import timezone
from wallet_app.models import Transaction, Withdrawal
from wallet_app.services import check_transfer_status # Adjust import path as necessary

# Map Monnify status codes to your local model status codes
STATUS_MAP = {
    "SUCCESS": "completed",
    "FAILED": "failed",
    "PENDING": "processing", # Still waiting
    "IN_PROGRESS": "processing",
    "EXTERNAL_ERROR": "failed", # Treat Monnify API errors as failed for safety
}


class Command(BaseCommand):
    help = 'Checks the status of pending Monnify withdrawal transactions and updates records.'

    def handle(self, *args, **kwargs):
        self.stdout.write(f"[{timezone.now()}] Starting check for pending transfers...")

        # Find all withdrawal transactions that are currently marked as 'Processing' (i.e., pending)
        pending_transactions = Transaction.objects.filter(
            status='processing'
        ).select_related('user').prefetch_related('pending_transfer_set') # Optimize query

        if not pending_transactions:
            self.stdout.write(self.style.NOTICE("No pending withdrawal transactions found."))
            return

        updates_count = 0
        
        for tx in pending_transactions:
            try:
                # 1. Check status with Monnify using the stored reference
                monnify_status_data = check_transfer_status(tx.reference)
                monnify_status = monnify_status_data.get("payment_status")
                
                # 2. Determine the local status
                new_status = STATUS_MAP.get(monnify_status, "processing") # Default to Processing if unknown
                
                # If status hasn't changed, skip update
                if new_status == tx.status:
                    self.stdout.write(f"Reference {tx.reference}: Status remains {new_status}. Skipping.")
                    continue

                # 3. Perform atomic update
                with db_transaction.atomic():
                    # Update the main Transaction record
                    tx.status = new_status
                    tx.save(update_fields=['status', 'updated_at'])

                    # Update the related Withdrawal record(s)
                    Withdrawal.objects.filter(
                        user=tx.user, 
                        transfer_reference=tx.reference
                    ).update(status=new_status)
                    
                    self.stdout.write(self.style.SUCCESS(f"Reference {tx.reference}: Status updated to {new_status}."))
                    updates_count += 1
                
                # 4. Handle failed transactions: reverse deduction if necessary
                if new_status == "Failed":
                    wallet = tx.user.wallet
                    wallet.balance += tx.amount # Reverse the deduction made in initiate_withdrawal
                    wallet.save(update_fields=['balance'])
                    self.stdout.write(self.style.WARNING(f"Reference {tx.reference}: Amount {tx.amount} reversed back to wallet."))

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error processing transaction {tx.reference}: {e}"))
                # Note: Transaction status remains 'Processing' until successful check

        self.stdout.write(f"[{timezone.now()}] Finished. Total updates: {updates_count}.")
