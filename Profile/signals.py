"""
Signal handlers for Profile app.
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


@receiver(post_save, sender='Packages.Package')
def notify_movers(sender, instance, created, **kwargs):
    """
    Signal to notify nearby movers when a new Package is created.
    Sends ride requests to users within the specified range radius.
    """
    if created:
        channel_layer = get_channel_layer()
        
        from Presence.models import UserPresence
        nearby_presence = UserPresence.objects.filter(
            is_online=True,
            current_latitude__isnull=False,
            current_longitude__isnull=False,
        )
        
        if instance.location_latitude and instance.location_longitude and instance.range_radius:
            radius = float(instance.range_radius)
            nearby_presence = nearby_presence.filter(
                current_latitude__gte=float(instance.location_latitude) - radius,
                current_latitude__lte=float(instance.location_latitude) + radius,
                current_longitude__gte=float(instance.location_longitude) - radius,
                current_longitude__lte=float(instance.location_longitude) + radius,
            )
        
        for presence in nearby_presence:
            async_to_sync(channel_layer.group_send)(
                f"user_{presence.user.id}",
                {
                    "type": "ride_request",
                    "package_id": str(instance.id),
                    "location": instance.location,
                    "destination": instance.destination,
                    "range_radius": str(instance.range_radius) if instance.range_radius else None,
                },
            )