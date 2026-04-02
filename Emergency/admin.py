from django.contrib import admin
from .models import EmergencySOS


@admin.register(EmergencySOS)
class EmergencySOSAdmin(admin.ModelAdmin):
    list_display = ('user', 'status', 'created_at', 'resolved_at')
    list_filter = ('status',)
    search_fields = ('user__email',)
    raw_id_fields = ('user', 'trip', 'acknowledged_by')