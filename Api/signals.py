# from django.db.models.signals import post_save
# from django.dispatch import receiver
# from wallet.services import create_dedicated_account_for_user
# from Api.models import User

# @receiver(post_save, sender=User)
# def create_dedicated_account_on_signup(sender, instance, created, **kwargs):
#     if created:
#         # Optional: wrap in try/except to avoid blocking registration if Monnify is down
#         try:
#             create_dedicated_account_for_user(instance)
#         except Exception as e:
#             # TODO: log / enqueue retry
#             pass