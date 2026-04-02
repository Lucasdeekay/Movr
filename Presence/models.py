from django.db import models
import uuid


class UUIDModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, db_column='id')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        ordering = ('-created_at',)
        verbose_name = 'UUID Model'
        verbose_name_plural = 'UUID Models'


class UserPresence(UUIDModel):
    """Track user online/offline status and location."""
    user = models.OneToOneField('Auth.CustomUser', on_delete=models.CASCADE, related_name='presence')
    is_online = models.BooleanField(default=False)
    last_seen = models.DateTimeField(auto_now=True)
    current_latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    current_longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    location_updated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "User Presence"
        verbose_name_plural = "User Presences"

    def __str__(self):
        return f"{self.user.email} - {'online' if self.is_online else 'offline'}"