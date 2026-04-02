from rest_framework import serializers
from .models import UserPresence


class UserPresenceSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = UserPresence
        fields = ['id', 'user', 'user_email', 'is_online', 'last_seen', 'current_latitude', 'current_longitude', 'location_updated_at']
        read_only_fields = ['id', 'user', 'last_seen', 'location_updated_at']