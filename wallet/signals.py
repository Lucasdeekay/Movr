from django.db.models.signals import post_save
from django.dispatch import receiver
from Api.models import User
from Api.models import Wallet

# Signal to create a Wallet for every new User
@receiver(post_save, sender=User)
def create_user_wallet(sender, instance, created, **kwargs):
    """
    Create a wallet for new users.
    
    Automatically creates a wallet when a new user is created.
    """
    if created:
        Wallet.objects.create(user=instance)


# Signal to save the Wallet when the User is saved
@receiver(post_save, sender=User)
def save_user_wallet(sender, instance, **kwargs):
    """
    Save user wallet when user is updated.
    
    Ensures wallet is saved when user is updated.
    """
    try:
        instance.wallet.save()
    except Wallet.DoesNotExist:
        # Create wallet if it doesn't exist (fallback)
        Wallet.objects.create(user=instance)
