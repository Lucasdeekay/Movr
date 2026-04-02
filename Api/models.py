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


class CustomUser(AbstractBaseUser, PermissionsMixin, UUIDModel):
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
        verbose_name = "User"
        verbose_name_plural = "Users"
        ordering = ("-date_joined",)

    def __str__(self):
        return f"{self.email}"


class KYC(UUIDModel):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='kyc')
    bvn = models.CharField(max_length=11, unique=True, null=True, blank=True)
    nin = models.CharField(max_length=11, unique=True, null=True, blank=True)
    driver_license = models.ImageField(upload_to='driver_license/', null=True, blank=True)
    verified = models.BooleanField(default=False)

    class Meta:
        verbose_name = "KYC"
        verbose_name_plural = "KYC Records"

    def __str__(self):
        return f"KYC for {self.user.email}"


class SocialMediaLink(UUIDModel):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='social_media')
    facebook = models.URLField(unique=True, null=True, blank=True)
    instagram = models.URLField(unique=True, null=True, blank=True)
    linkedin = models.URLField(unique=True, null=True, blank=True)

    class Meta:
        verbose_name = "Social Media Link"
        verbose_name_plural = "Social Media Links"

    def __str__(self):
        return f"Social media link for {self.user.email}"


class Vehicle(UUIDModel):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='vehicle')
    vehicle_plate_number = models.CharField(max_length=50, unique=True, null=True, blank=True)
    vehicle_type = models.CharField(max_length=50, null=True, blank=True)
    vehicle_brand = models.CharField(max_length=50, null=True, blank=True)
    vehicle_color = models.CharField(max_length=25, null=True, blank=True)
    vehicle_photo = models.ImageField(upload_to='vehicle_photo/', null=True, blank=True)
    driver_license = models.ImageField(upload_to='driver_license/', null=True, blank=True)
    vehicle_inspector_report = models.ImageField(upload_to='vehicle_inspector_report/', null=True, blank=True)
    vehicle_insurance = models.ImageField(upload_to='vehicle_insurance/', null=True, blank=True)

    class Meta:
        verbose_name = "Vehicle"
        verbose_name_plural = "Vehicles"

    def __str__(self):
        return f"Vehicle Details for {self.user.email}"


class SubscriptionPlan(UUIDModel):
    NAME_CHOICES = (('free', 'FREE'), ('basic', 'BASIC'), ('rover', 'ROVER'), ('courier', 'COURIER'), ('courier_plus', 'COURIER PLUS'))
    PRICE_CHOICES = ((Decimal(0.00), '#0.00'), (Decimal(1200.00), '#1,200'), (Decimal(4500.00), '#4,500'), (Decimal(9400.00), '#9,400'), (Decimal(15200.00), '#15,200'))
    name = models.CharField(max_length=100, default='free', choices=NAME_CHOICES)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal(0.00), choices=PRICE_CHOICES)
    duration = models.IntegerField(default=30)

    class Meta:
        verbose_name = "Subscription Plan"
        verbose_name_plural = "Subscription Plans"

    def __str__(self):
        return self.name


class Subscription(UUIDModel):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='subscriptions')
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.CASCADE)
    start_date = models.DateField(auto_now_add=True)
    end_date = models.DateField(blank=True, null=True)

    class Meta:
        verbose_name = "Subscription"
        verbose_name_plural = "Subscriptions"

    def __str__(self):
        return f"{self.user.email} - {self.plan.name}"


class OTP(UUIDModel):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='otp')
    code = models.CharField(max_length=4)
    is_used = models.BooleanField(default=False)
    expires_at = models.DateTimeField()

    class Meta:
        verbose_name = "OTP"
        verbose_name_plural = "OTPs"
        unique_together = ("user", "code")

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
        send_mail('Your OTP Code', f'Your OTP code is {self.code}. It expires in 1 hour.', settings.EMAIL_HOST_USER, [self.user.email], fail_silently=False)


class Badge(UUIDModel):
    name = models.CharField(max_length=100)
    description = models.TextField()
    icon = models.ImageField(upload_to='badge_icons/', null=True, blank=True)
    criteria = models.CharField(max_length=255)

    class Meta:
        verbose_name = "Badge"
        verbose_name_plural = "Badges"

    def __str__(self):
        return self.name


class UserBadge(UUIDModel):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='badges')
    badge = models.ForeignKey(Badge, on_delete=models.CASCADE)
    awarded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "User Badge"
        verbose_name_plural = "User Badges"

    def __str__(self):
        return f"{self.user.email} - {self.badge.name}"


class ReferralToken(UUIDModel):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='referral_token')
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    class Meta:
        verbose_name = "Referral Token"
        verbose_name_plural = "Referral Tokens"

    def __str__(self):
        return f"{self.user.email}'s Referral Token"


class Referral(UUIDModel):
    referred_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='referrals')
    referred_user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='referred_details')
    token_used = models.UUIDField()

    class Meta:
        verbose_name = "Referral"
        verbose_name_plural = "Referrals"

    def __str__(self):
        return f"{self.referred_user.email} referred by {self.referred_by.email if self.referred_by else 'Unknown'}"

    @staticmethod
    def create_referral(referred_user, token):
        try:
            referrer = ReferralToken.objects.get(token=token).user
        except ReferralToken.DoesNotExist:
            referrer = None
        Referral.objects.create(referred_by=referrer, referred_user=referred_user, token_used=token)


class Notification(UUIDModel):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="notifications")
    title = models.CharField(max_length=200, null=True, blank=True)
    message = models.TextField()
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Notification"
        verbose_name_plural = "Notifications"

    def __str__(self):
        return f"Notification for {self.user.email} - {self.title or 'No Title'}"

    def mark_as_read(self):
        self.is_read = True
        self.save(update_fields=['is_read'])

    @classmethod
    def get_unread_count(cls, user):
        return cls.objects.filter(user=user, is_read=False).count()
