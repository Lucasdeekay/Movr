from django.contrib import admin
from .models import Route, ScheduledRoute, Day


@admin.register(Route)
class RouteAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'location', 'destination', 'transportation_mode', 'is_live', 'created_at']
    list_filter = ['is_live', 'transportation_mode', 'service_type']
    search_fields = ['location', 'destination', 'user__email']
    raw_id_fields = ['user']


@admin.register(ScheduledRoute)
class ScheduledRouteAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'route', 'start_date', 'end_date', 'is_active', 'created_at']
    list_filter = ['is_active']
    search_fields = ['user__email', 'route__location']
    raw_id_fields = ['user', 'route', 'days']


@admin.register(Day)
class DayAdmin(admin.ModelAdmin):
    list_display = ['id', 'name']
    search_fields = ['name']