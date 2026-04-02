from django.db import models
from Api.models import UUIDModel


class Day(UUIDModel):
    """
    Model representing days of the week for scheduled routes.
    """
    name = models.CharField(max_length=20, unique=True)

    class Meta:
        verbose_name = "Day"
        verbose_name_plural = "Days"

    def __str__(self):
        return self.name


class Route(UUIDModel):
    """
    Model representing a user's travel route from location to destination.
    """
    user = models.ForeignKey(
        'Api.CustomUser', 
        on_delete=models.CASCADE, 
        related_name='routes',
        help_text='User who created this route'
    )
    location = models.CharField(max_length=255, help_text='Starting location name')
    location_latitude = models.DecimalField(
        max_digits=9, decimal_places=6, null=True, blank=True,
        help_text='Starting location latitude'
    )
    location_longitude = models.DecimalField(
        max_digits=9, decimal_places=6, null=True, blank=True,
        help_text='Starting location longitude'
    )
    destination = models.CharField(max_length=255, help_text='Destination location name')
    destination_latitude = models.DecimalField(
        max_digits=9, decimal_places=6, null=True, blank=True,
        help_text='Destination latitude'
    )
    destination_longitude = models.DecimalField(
        max_digits=9, decimal_places=6, null=True, blank=True,
        help_text='Destination longitude'
    )
    transportation_mode = models.CharField(
        max_length=50, 
        choices=[
            ('car', 'Car'),
            ('bike', 'Bike'),
            ('bus', 'Bus'),
            ('train', 'Train'),
            ('walking', 'Walking'),
        ],
        help_text='Mode of transportation'
    )
    departure_time = models.DateTimeField(help_text='Scheduled departure time')
    is_live = models.BooleanField(default=False, help_text='Whether route is currently live')
    service_type = models.CharField(
        max_length=20,
        choices=[
            ('ride', 'Ride'),
            ('delivery', 'Delivery'),
        ],
        default='ride',
        help_text='Type of service'
    )

    class Meta:
        verbose_name = "Route"
        verbose_name_plural = "Routes"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.location} to {self.destination}"


class ScheduledRoute(UUIDModel):
    """
    Model representing a recurring scheduled route.
    """
    user = models.ForeignKey(
        'Api.CustomUser', 
        on_delete=models.CASCADE, 
        related_name='scheduled_routes',
        help_text='User who created this scheduled route'
    )
    route = models.ForeignKey(
        Route, 
        on_delete=models.CASCADE, 
        related_name='scheduled_routes',
        help_text='Base route for this schedule'
    )
    days = models.ManyToManyField(
        Day, 
        related_name='scheduled_routes',
        help_text='Days of the week when this route runs'
    )
    start_date = models.DateField(help_text='Schedule start date')
    end_date = models.DateField(null=True, blank=True, help_text='Schedule end date')
    departure_time = models.TimeField(help_text='Daily departure time')
    is_active = models.BooleanField(default=True, help_text='Whether schedule is active')

    class Meta:
        verbose_name = "Scheduled Route"
        verbose_name_plural = "Scheduled Routes"
        ordering = ['-created_at']

    def __str__(self):
        return f"Scheduled: {self.route.location} to {self.route.destination}"