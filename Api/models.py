import datetime
import random
import string
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

    def save(self, *args, **kwargs):
        # If end_date is not set, calculate it based on start_date and plan duration
        if not self.end_date:
            if hasattr(self.plan, 'duration'):
                self.end_date = self.start_date + datetime.timedelta(days=self.plan.duration)
            else:
                raise ValidationError("The plan must have a duration attribute.")

        # Ensure that end_date is not before start_date
        if self.end_date < self.start_date:
            raise ValidationError("end_date cannot be before start_date.")

        super().save(*args, **kwargs)

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

    user = models.ForeignKey('CustomUser', on_delete=models.CASCADE, related_name='routes')
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
        self.qr_image.save(f'{self.package.id}_qr.png', File(buffer), save=False)
        super().save(*args, **kwargs)


class PackageOffer(models.Model):
    package_bid = models.ForeignKey(Bid, on_delete=models.CASCADE, related_name='package_offers')
    qr_code = models.ForeignKey(QRCode, on_delete=models.CASCADE, related_name='package_offers')
    is_picked_up = models.BooleanField(default=False)
    is_delivered = models.BooleanField(default=False)

    def __str__(self):
        return f"Package Offer for {self.package_bid.package.location} to {self.package_bid.package.destination}"


# class RideMatch(models.Model):
#     travel_plan = models.ForeignKey(TravelPlan, on_delete=models.CASCADE, related_name='matches')
#     matched_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='matches')
#     status = models.CharField(max_length=50, choices=[('pending', 'Pending'), ('accepted', 'Accepted'), ('completed', 'Completed')], default='pending')
#
#     def __str__(self):
#         return f"{self.travel_plan} - Matched with {self.matched_user.username}"
#
# class RideTracking(models.Model):
#     ride_match = models.OneToOneField(RideMatch, on_delete=models.CASCADE, related_name='tracking')
#     current_location = models.CharField(max_length=255)
#     updated_at = models.DateTimeField(auto_now=True)
#
#     def __str__(self):
#         return f"Tracking for {self.ride_match}"
#
# # Delivery Services Models
# class Insurance(models.Model):
#     travel_plan = models.OneToOneField(TravelPlan, on_delete=models.CASCADE, related_name='insurance')
#     insurance_company = models.CharField(max_length=100)
#     coverage_amount = models.DecimalField(max_digits=10, decimal_places=2)
#     fee = models.DecimalField(max_digits=10, decimal_places=2)
#
#     def __str__(self):
#         return f"Insurance for {self.travel_plan}"
#
# class DamageReport(models.Model):
#     travel_plan = models.ForeignKey(TravelPlan, on_delete=models.CASCADE, related_name='damage_reports')
#     description = models.TextField()
#     reported_at = models.DateTimeField(auto_now_add=True)
#     photo = models.ImageField(upload_to='damage_photos/', null=True, blank=True)
#     video = models.FileField(upload_to='damage_videos/', null=True, blank=True)
#
#     def __str__(self):
#         return f"Damage report for {self.travel_plan}"
#
# # Safety Features Models
# class HomeAwayStatus(models.Model):
#     user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='home_away_status')
#     is_home = models.BooleanField(default=True)
#     location = models.CharField(max_length=100)
#
#     def __str__(self):
#         return f"{self.user.username} - {'Home' if self.is_home else 'Away'}"
#
# class SOSAlert(models.Model):
#     user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sos_alerts')
#     ride = models.ForeignKey(RideMatch, on_delete=models.CASCADE, related_name='sos_alerts')
#     message = models.CharField(max_length=255)
#     sent_at = models.DateTimeField(auto_now_add=True)
#     coordinates = models.CharField(max_length=100)
#
#     def __str__(self):
#         return f"SOS Alert by {self.user.username}"
#
# class Badge(models.Model):
#     name = models.CharField(max_length=100)
#     description = models.TextField()
#     icon = models.ImageField(upload_to='badge_icons/', null=True, blank=True)
#     criteria = models.CharField(max_length=255)
#
#     def __str__(self):
#         return self.name
#
# class UserBadge(models.Model):
#     user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='badges')
#     badge = models.ForeignKey(Badge, on_delete=models.CASCADE)
#     awarded_at = models.DateTimeField(auto_now_add=True)
#
#     def __str__(self):
#         return f"{self.user.username} - {self.badge.name}"
#
# class Review(models.Model):
#     ride_match = models.ForeignKey(RideMatch, on_delete=models.CASCADE, related_name='reviews')
#     reviewer = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='given_reviews')
#     rating = models.IntegerField()
#     comment = models.TextField()
#     created_at = models.DateTimeField(auto_now_add=True)
#
#     def __str__(self):
#         return f"Review by {self.reviewer.username} for {self.ride_match}"
