from django.db import models
from Api.models import UUIDModel


class Package(UUIDModel):
    """
    Model representing a package delivery request.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('in_transit', 'In Transit'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]

    user = models.ForeignKey(
        'Api.CustomUser',
        on_delete=models.CASCADE,
        related_name='packages',
        help_text='User who created this package request'
    )
    location = models.CharField(max_length=255, help_text='Pickup location')
    location_latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    location_longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    destination = models.CharField(max_length=255, help_text='Delivery destination')
    destination_latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    destination_longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    package_type = models.CharField(max_length=50, choices=[('Delivery', 'Delivery'), ('Ride', 'Ride')], default='Delivery')
    item_image = models.ImageField(upload_to='package_images/', null=True, blank=True)
    item_description = models.TextField(null=True, blank=True)
    item_weight = models.CharField(max_length=20, choices=[('light', 'Light'), ('medium', 'Medium'), ('heavy', 'Heavy')])
    receiver_name = models.CharField(max_length=100)
    receiver_phone_number = models.CharField(max_length=15)
    range_radius = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True, help_text='Radius in km')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    scheduled_pickup_time = models.DateTimeField(null=True, blank=True)
    scheduled_delivery_time = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Package"
        verbose_name_plural = "Packages"

    def __str__(self):
        return f"Package {self.id} - {self.location} to {self.destination}"


class Bid(UUIDModel):
    """
    Model representing a bid on a package.
    """
    package = models.ForeignKey(Package, on_delete=models.CASCADE, related_name='bids')
    bidder = models.ForeignKey('Api.CustomUser', on_delete=models.CASCADE, related_name='bids')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    message = models.TextField(null=True, blank=True)
    estimated_arrival = models.DateTimeField(null=True, blank=True)
    is_accepted = models.BooleanField(default=False)
    is_rejected = models.BooleanField(default=False)

    class Meta:
        verbose_name = "Bid"
        verbose_name_plural = "Bids"
        ordering = ['-created_at']

    def __str__(self):
        return f"Bid {self.id} - {self.bidder.email} - ${self.amount}"


class PackageOffer(UUIDModel):
    """
    Model representing an accepted bid/offer for package delivery.
    """
    package = models.ForeignKey(Package, on_delete=models.CASCADE, related_name='offers')
    bid = models.OneToOneField(Bid, on_delete=models.CASCADE, related_name='offer')
    driver = models.ForeignKey('Api.CustomUser', on_delete=models.CASCADE, related_name='accepted_offers')
    agreed_amount = models.DecimalField(max_digits=10, decimal_places=2)
    picked_up = models.BooleanField(default=False)
    picked_up_at = models.DateTimeField(null=True, blank=True)
    delivered = models.BooleanField(default=False)
    delivered_at = models.DateTimeField(null=True, blank=True)
    is_cancelled = models.BooleanField(default=False)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    cancellation_reason = models.TextField(null=True, blank=True)
    current_latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    current_longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)

    class Meta:
        verbose_name = "Package Offer"
        verbose_name_plural = "Package Offers"

    def __str__(self):
        return f"Offer {self.id} - Package {self.package.id} - Driver {self.driver.email}"


class QRCode(UUIDModel):
    """
    Model for QR codes associated with packages for tracking.
    """
    package = models.ForeignKey(Package, on_delete=models.CASCADE, related_name='qrcodes')
    code = models.CharField(max_length=255, unique=True)
    is_scanned = models.BooleanField(default=False)
    scanned_at = models.DateTimeField(null=True, blank=True)
    scanned_location = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        verbose_name = "QR Code"
        verbose_name_plural = "QR Codes"

    def __str__(self):
        return f"QR Code for Package {self.package.id}"