from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from decimal import Decimal

from Api.models import SubscriptionPlan, Day

User = get_user_model()

class Command(BaseCommand):
    help = "Seed initial data: Admin, Subscription Plans, Days"

    def handle(self, *args, **kwargs):
        self.stdout.write("🌱 Seeding data...")

        # --- 1. Create Admin User ---
        admin_email = "admin@movr.com"
        admin_password = "Admin12345"

        if not User.objects.filter(email=admin_email).exists():
            User.objects.create_superuser(
                email=admin_email,
                password=admin_password,
                first_name="Admin",
                last_name="User",
            )
            self.stdout.write(self.style.SUCCESS(f"✔ Created admin user: {admin_email}"))
        else:
            self.stdout.write(self.style.WARNING("Admin user already exists"))

        # --- 2. Create Subscription Plans ---
        plans = [
            ("free", Decimal("0.00"), 30),
            ("basic", Decimal("1200.00"), 30),
            ("rover", Decimal("4500.00"), 30),
            ("courier", Decimal("9400.00"), 30),
            ("courier_plus", Decimal("15200.00"), 30),
        ]

        for name, price, duration in plans:
            if not SubscriptionPlan.objects.filter(name=name).exists():
                SubscriptionPlan.objects.create(
                    name=name,
                    price=price,
                    duration=duration
                )
                self.stdout.write(self.style.SUCCESS(f"✔ Created plan: {name}"))
            else:
                self.stdout.write(self.style.WARNING(f"Plan '{name}' already exists"))

        # --- 3. Create Days of the Week ---
        days = [
            ("monday", "Monday"),
            ("tuesday", "Tuesday"),
            ("wednesday", "Wednesday"),
            ("thursday", "Thursday"),
            ("friday", "Friday"),
            ("saturday", "Saturday"),
            ("sunday", "Sunday"),
        ]

        for key, label in days:
            if not Day.objects.filter(name=key).exists():
                Day.objects.create(name=key)
                self.stdout.write(self.style.SUCCESS(f"✔ Created day: {label}"))
            else:
                self.stdout.write(self.style.WARNING(f"Day '{label}' already exists"))

        self.stdout.write(self.style.SUCCESS("🎉 Seeding complete!"))
