from rest_framework import serializers
from .models import Package, Bid, PackageOffer, QRCode


class PackageSerializer(serializers.ModelSerializer):
    user_email = serializers.ReadOnlyField(source='user.email')
    
    class Meta:
        model = Package
        fields = [
            'id', 'user', 'user_email', 'location', 'location_latitude', 'location_longitude',
            'destination', 'destination_latitude', 'destination_longitude', 'package_type',
            'item_image', 'item_description', 'item_weight', 'receiver_name', 'receiver_phone_number',
            'range_radius', 'status', 'scheduled_pickup_time', 'scheduled_delivery_time',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class BidSerializer(serializers.ModelSerializer):
    bidder_email = serializers.ReadOnlyField(source='bidder.email')
    package_location = serializers.ReadOnlyField(source='package.location')
    package_destination = serializers.ReadOnlyField(source='package.destination')
    
    class Meta:
        model = Bid
        fields = [
            'id', 'package', 'package_location', 'package_destination',
            'bidder', 'bidder_email', 'amount', 'message', 'estimated_arrival',
            'is_accepted', 'is_rejected', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'is_accepted', 'is_rejected']


class PackageOfferSerializer(serializers.ModelSerializer):
    driver_email = serializers.ReadOnlyField(source='driver.email')
    package_details = PackageSerializer(source='package', read_only=True)
    bid_amount = serializers.ReadOnlyField(source='bid.amount')
    
    class Meta:
        model = PackageOffer
        fields = [
            'id', 'package', 'package_details', 'bid', 'bid_amount',
            'driver', 'driver_email', 'agreed_amount', 'picked_up', 'picked_up_at',
            'delivered', 'delivered_at', 'is_cancelled', 'cancelled_at',
            'cancellation_reason', 'current_latitude', 'current_longitude',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class QRCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = QRCode
        fields = ['id', 'package', 'code', 'is_scanned', 'scanned_at', 'scanned_location', 'created_at']
        read_only_fields = ['id', 'created_at']