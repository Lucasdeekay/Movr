from django.contrib import admin
from .models import UserPresence


@admin.register(UserPresence)
class UserPresenceAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_online', 'last_seen', 'location_updated_at')
    list_filter = ('is_online',)
    search_fields = ('user__email',)
    raw_id_fields = ('user',)