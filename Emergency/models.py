from django.db import models
from Api.models import UUIDModel


class EmergencySOS(UUIDModel):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('acknowledged', 'Acknowledged'),
        ('resolved', 'Resolved'),
        ('cancelled', 'Cancelled'),
    ]

    user = models.ForeignKey('Api.CustomUser', on_delete=models.CASCADE, related_name='sos_alerts', help_text='User who triggered the SOS')
    trip = models.ForeignKey('Packages.PackageOffer', on_delete=models.CASCADE, null=True, blank=True, related_name='sos_alerts', help_text='Trip during which SOS was triggered')
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, help_text='Location latitude where SOS was triggered')
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, help_text='Location longitude where SOS was triggered')
    message = models.TextField(null=True, blank=True, help_text='Optional message from user')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', help_text='Current status of the SOS alert')
    acknowledged_by = models.ForeignKey('Api.CustomUser', on_delete=models.SET_NULL, null=True, blank=True, related_name='acknowledged_sos', help_text='Admin who acknowledged the SOS')
    resolved_at = models.DateTimeField(null=True, blank=True, help_text='When the SOS was resolved')

    class Meta:
        verbose_name = "Emergency SOS"
        verbose_name_plural = "Emergency SOS Alerts"
        ordering = ('-created_at',)

    def __str__(self):
        return f"SOS by {self.user.email} - {self.status}"