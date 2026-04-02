from rest_framework import serializers
from .models import Route, ScheduledRoute, Day


class DaySerializer(serializers.ModelSerializer):
    class Meta:
        model = Day
        fields = ['id', 'name', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class RouteSerializer(serializers.ModelSerializer):
    user_email = serializers.ReadOnlyField(source='user.email')
    
    class Meta:
        model = Route
        fields = [
            'id', 'user', 'user_email', 'location', 'location_latitude', 
            'location_longitude', 'destination', 'destination_latitude', 
            'destination_longitude', 'transportation_mode', 'departure_time',
            'is_live', 'service_type', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class ScheduledRouteSerializer(serializers.ModelSerializer):
    route_details = RouteSerializer(source='route', read_only=True)
    days_details = DaySerializer(many=True, read_only=True)
    user_email = serializers.ReadOnlyField(source='user.email')
    
    class Meta:
        model = ScheduledRoute
        fields = [
            'id', 'user', 'user_email', 'route', 'route_details', 
            'days', 'days_details', 'start_date', 'end_date', 
            'departure_time', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']