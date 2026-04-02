from rest_framework import serializers
from .models import EmergencySOS


class EmergencySOSSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source='user.email', read_only=True)
    acknowledged_by_email = serializers.EmailField(source='acknowledged_by.email', read_only=True)

    class Meta:
        model = EmergencySOS
        fields = ['id', 'user', 'user_email', 'trip', 'latitude', 'longitude', 'message', 'status', 'acknowledged_by', 'acknowledged_by_email', 'resolved_at', 'created_at']
        read_only_fields = ['id', 'user', 'status', 'acknowledged_by', 'resolved_at', 'created_at']