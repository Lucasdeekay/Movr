import datetime
import random
import string
import uuid

from _decimal import Decimal

from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.db import models
from django.contrib.auth.models import PermissionsMixin
from django.utils import timezone
import qrcode
from io import BytesIO
from django.core.files import File
from django.utils.translation import gettext_lazy as _

from Movr import settings


# User Manager
class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, password, **extra_fields)


# Custom User Model
class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=50, null=True, blank=True)
    last_name = models.CharField(max_length=50, null=True, blank=True)
    phone_number = models.CharField(max_length=15, unique=True, null=True, blank=True)
    is_email_verified = models.BooleanField(default=False)
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    two_factor_enabled = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'

    class Meta:
        abstract = False

    def __str__(self):
        return f"{self.email}"


class KYC(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='kyc')
    bvn = models.CharField(max_length=11, unique=True, null=True, blank=True)
    nin = models.CharField(max_length=11, unique=True, null=True, blank=True)
    driver_license = models.ImageField(upload_to='driver_license/', null=True, blank=True)
    verified = models.BooleanField(default=False)

    def __str__(self):
        return f"KYC for {self.user.username}"


class SocialMediaLink(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='social_media')
    facebook = models.URLField(unique=True, null=True, blank=True)
    instagram = models.URLField(unique=True, null=True, blank=True)
    linkedin = models.URLField(unique=True, null=True, blank=True)

    def __str__(self):
        return f"Social media link for {self.user.username}"


class Vehicle(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='vehicle')
    vehicle_plate_number = models.CharField(max_length=50, unique=True, null=True, blank=True)
    vehicle_type = models.CharField(max_length=50, null=True, blank=True)
    vehicle_brand = models.CharField(max_length=50, null=True, blank=True)
    vehicle_color = models.CharField(max_length=25, null=True, blank=True)
    vehicle_photo = models.ImageField(upload_to='vehicle_photo/', null=True, blank=True)
    driver_license = models.ImageField(upload_to='driver_license/', null=True, blank=True)
    vehicle_inspector_report = models.ImageField(upload_to='vehicle_inspector_report/', null=True, blank=True)
    vehicle_insurance = models.ImageField(upload_to='vehicle_insurance/', null=True, blank=True)

    def __str__(self):
        return f"Vehicle Details for {self.user.username}"


# Payment Models
class PaymentMethod(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='payment_methods')
    method_name = models.CharField(max_length=50)
    account_details = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.method_name} - {self.user.username}"


# Paystack DVA Models
class PaystackAccount(models.Model):
    """
    Model to store Paystack DVA (Direct Virtual Account) information
    """
    ACCOUNT_TYPE_CHOICES = [
        ('dva', 'Direct Virtual Account'),
        ('standard', 'Standard Account'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('pending', 'Pending'),
        ('suspended', 'Suspended'),
    ]
    
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='paystack_account')
    account_type = models.CharField(max_length=20, choices=ACCOUNT_TYPE_CHOICES, default='dva')
    account_number = models.CharField(max_length=20, unique=True, null=True, blank=True)
    bank_name = models.CharField(max_length=100, null=True, blank=True)
    bank_code = models.CharField(max_length=10, null=True, blank=True)
    paystack_customer_code = models.CharField(max_length=100, null=True, blank=True)
    paystack_account_id = models.CharField(max_length=100, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Paystack Account for {self.user.email} - {self.account_number}"
    
    class Meta:
        verbose_name = "Paystack Account"
        verbose_name_plural = "Paystack Accounts"


class PaystackTransaction(models.Model):
    """
    Model to track Paystack transactions
    """
    TRANSACTION_TYPE_CHOICES = [
        ('deposit', 'Deposit'),
        ('withdrawal', 'Withdrawal'),
        ('transfer', 'Transfer'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('abandoned', 'Abandoned'),
        ('reversed', 'Reversed'),
    ]
    
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='paystack_transactions')
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPE_CHOICES)
    paystack_reference = models.CharField(max_length=100, unique=True)
    paystack_transaction_id = models.CharField(max_length=100, null=True, blank=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3, default='NGN')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    gateway_response = models.TextField(null=True, blank=True)
    channel = models.CharField(max_length=50, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    narration = models.CharField(max_length=255, null=True, blank=True)
    fees = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal('0.00'))
    paid_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.email} - {self.transaction_type} - {self.amount} ({self.status})"
    
    class Meta:
        verbose_name = "Paystack Transaction"
        verbose_name_plural = "Paystack Transactions"
        ordering = ['-created_at']


class SubscriptionPlan(models.Model):
    NAME_CHOICES = (
        ('free', 'FREE'),
        ('basic', 'BASIC'),
        ('rover', 'ROVER'),
        ('courier', 'COURIER'),
        ('courier_plus', 'COURIER PLUS'),
    )
    PRICE_CHOICES = (
        (Decimal(0.00), '#0.00'),
        (Decimal(1200.00), '#1,200'),
        (Decimal(4500.00), '#4,500'),
        (Decimal(9400.00), '#9,400'),
        (Decimal(15200.00), '#15,200')
    )
    name = models.CharField(max_length=100, default='free', choices=NAME_CHOICES)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal(0.00), choices=PRICE_CHOICES)
    duration = models.IntegerField(default=30, help_text="Duration in days")

    def __str__(self):
        return self.name


class Subscription(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='subscriptions')
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.CASCADE)
    start_date = models.DateField(auto_now_add=True)
    end_date = models.DateField(blank=True, null=True)  # Allow end_date to be blank initially

    def __str__(self):
        return f"{self.user.email} - {self.plan.name}"


class OTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='otp')
    code = models.CharField(max_length=4, unique=True)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        self.expires_at = timezone.now() + timezone.timedelta(hours=1)
        if not self.code:
            self.code = ''.join(random.choices(string.digits, k=4))
        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.user.email} - {self.code}'

    def is_expired(self):
        return timezone.now() > self.expires_at

    def send_otp(self):
        # You can use any email sending method here
        send_mail(
            'Your OTP Code',
            f'Your OTP code is {self.code}. It expires in 1 hour.',
            settings.EMAIL_HOST_USER,
            [self.user.email],
            fail_silently=False,
        )


class Day(models.Model):
    DAY_CHOICES = [
        ('monday', 'Monday'),
        ('tuesday', 'Tuesday'),
        ('wednesday', 'Wednesday'),
        ('thursday', 'Thursday'),
        ('friday', 'Friday'),
        ('saturday', 'Saturday'),
        ('sunday', 'Sunday'),
    ]
    name = models.CharField(max_length=10, choices=DAY_CHOICES, unique=True)

    def __str__(self):
        return self.name


class Route(models.Model):
    TRANSPORTATION_MODE_CHOICES = [
        ('public', 'Public'),
        ('bike', 'Bike'),
        ('car', 'Car'),
        ('train', 'Train'),
        ('bus', 'Bus'),
        ('aeroplane', 'Aeroplane'),
    ]

    SERVICE_TYPE_CHOICES = [
        ('ride', 'Ride'),
        ('delivery', 'Delivery'),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='routes')
    title = models.CharField(max_length=255)
    location = models.CharField(max_length=255)
    location_latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    location_longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    destination = models.CharField(max_length=255)
    destination_latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    destination_longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    stop_location = models.CharField(max_length=255, null=True, blank=True)
    stop_location_latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    stop_location_longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    transportation_mode = models.CharField(max_length=20, choices=TRANSPORTATION_MODE_CHOICES)
    service_type = models.CharField(max_length=20, choices=SERVICE_TYPE_CHOICES, null=True, blank=True)
    departure_time = models.DateTimeField()
    ticket_image = models.ImageField(upload_to='tickets/', null=True, blank=True)
    is_live = models.BooleanField(default=True)
    radius_range = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True, help_text="Radius in km")

    def __str__(self):
        return f"Route from {self.location} to {self.destination} by {self.user.email}"


class ScheduledRoute(models.Model):
    route = models.OneToOneField(Route, on_delete=models.CASCADE, related_name='scheduled_route')
    is_returning = models.BooleanField(default=False)
    returning_time = models.DateTimeField(null=True, blank=True)
    is_repeated = models.BooleanField(default=False)
    days_of_week = models.ManyToManyField('Day', blank=True)

    def __str__(self):
        return f"Scheduled Route for {self.route.user.email} from {self.route.location} to {self.route.destination}"


class Package(models.Model):
    WEIGHT_CHOICES = [
        ('light', 'Light'),
        ('medium', 'Medium'),
        ('heavy', 'Heavy'),
    ]
    PACKAGE_TYPE = [
        ('Delivery', 'Delivery'),
        ('Rideshare', 'Rideshare'),
        ('Schedule', 'Schedule'),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='packages')
    location = models.CharField(max_length=255)
    location_latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    location_longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    destination = models.CharField(max_length=255)
    destination_latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    destination_longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    package_type = models.CharField(max_length=20, choices=PACKAGE_TYPE)
    item_image = models.ImageField(upload_to='package_images/', null=True, blank=True)
    item_description = models.TextField(null=True, blank=True)
    item_weight = models.CharField(max_length=10, null=True, blank=True, choices=WEIGHT_CHOICES)
    receiver_name = models.CharField(null=True, blank=True, max_length=100)
    receiver_phone_number = models.CharField(null=True, blank=True, max_length=15)
    range_radius = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True, help_text="Radius in km")

    def __str__(self):
        return f"Package from {self.location} to {self.destination} by {self.user.email}"


# Bid Model
class Bid(models.Model):
    package = models.ForeignKey(Package, on_delete=models.CASCADE, related_name='bids')
    mover = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='bids')
    price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Bid by {self.mover.email} for {self.price}"


# QR Code Model
class QRCode(models.Model):
    code = models.CharField(max_length=6, unique=True)
    qr_image = models.ImageField(upload_to='qr_codes/', null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.code:
            self.code = ''.join(random.choices(string.digits, k=6))

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(self.code)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')

        # Save the QR code image
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        self.qr_image.save(f'{self.code}_qr.png', File(buffer), save=False)
        super().save(*args, **kwargs)


class PackageOffer(models.Model):
    package_bid = models.ForeignKey(Bid, on_delete=models.CASCADE, related_name='package_offers')
    qr_code = models.ForeignKey(QRCode, on_delete=models.CASCADE, related_name='package_offers')
    is_picked_up = models.BooleanField(default=False)
    is_delivered = models.BooleanField(default=False)
    is_scheduled = models.BooleanField(default=False)  # New field to indicate scheduling
    is_cancelled = models.BooleanField(default=False)  # New field to track cancellations

    def __str__(self):
        return f"Package Offer for {self.package_bid.package.location} to {self.package_bid.package.destination}"


class Wallet(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name="wallet")
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))

    def deposit(self, amount):
        self.balance += Decimal(amount)
        self.save()

    def withdraw(self, amount):
        if amount > self.balance:
            raise ValueError("Insufficient funds")
        self.balance -= Decimal(amount)
        self.save()

    def __str__(self):
        return f"{self.user.email} - Balance: {self.balance}"


class Transaction(models.Model):
    TRANSACTION_TYPE_CHOICES = [
        ("deposit", "Deposit"),
        ("withdrawal", "Withdrawal"),
        ("transfer", "Transfer"),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="transactions")
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPE_CHOICES)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    timestamp = models.DateTimeField(default=timezone.now)
    description = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.email} - {self.transaction_type.capitalize()} - {self.amount}"


class Transfer(models.Model):
    sender = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="transfers_sent")
    recipient = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="transfers_received")
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    timestamp = models.DateTimeField(default=timezone.now)
    message = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.sender.email} -> {self.recipient.email}: {self.amount}"


class WithdrawalRequest(models.Model):
    """
    Model to handle withdrawal requests.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="withdrawal_requests",
        verbose_name=_("User")
    )
    amount = models.DecimalField(
        max_digits=10, decimal_places=2,
        verbose_name=_("Amount")
    )
    bank_name = models.CharField(
        max_length=100,
        verbose_name=_("Bank Name")
    )
    account_number = models.CharField(
        max_length=20,
        verbose_name=_("Account Number")
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
        verbose_name=_("Status")
    )
    reason = models.TextField(
        null=True,
        blank=True,
        verbose_name=_("Reason for Rejection")
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Created At")
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name=_("Updated At")
    )

    def __str__(self):
        return f"Withdrawal Request {self.id} - {self.user.email} - {self.amount} ({self.status})"


class Badge(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    icon = models.ImageField(upload_to='badge_icons/', null=True, blank=True)
    criteria = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class UserBadge(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='badges')
    badge = models.ForeignKey(Badge, on_delete=models.CASCADE)
    awarded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.badge.name}"


class ReferralToken(models.Model):
    """
    Represents a unique referral token for a user.
    """
    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='referral_token'
    )
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}'s Referral Token"


class Referral(models.Model):
    """
    Represents a referral made by a user using a referral token.
    """
    referred_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='referrals'
    )
    referred_user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='referred_details'
    )
    token_used = models.UUIDField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.referred_user.username} referred by {self.referred_by.username if self.referred_by else 'Unknown'}"

    @staticmethod
    def create_referral(referred_user, token):
        """
        Static method to create a referral.
        """
        try:
            referrer = ReferralToken.objects.get(token=token).user
        except ReferralToken.DoesNotExist:
            referrer = None

        Referral.objects.create(
            referred_by=referrer,
            referred_user=referred_user,
            token_used=token
        )


