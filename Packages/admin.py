from django.contrib import admin
from .models import Package, Bid, PackageOffer, QRCode


@admin.register(Package)
class PackageAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'location', 'destination', 'status', 'item_weight', 'created_at']
    list_filter = ['status', 'package_type', 'item_weight']
    search_fields = ['location', 'destination', 'user__email', 'receiver_name']
    raw_id_fields = ['user']


@admin.register(Bid)
class BidAdmin(admin.ModelAdmin):
    list_display = ['id', 'package', 'bidder', 'amount', 'is_accepted', 'is_rejected', 'created_at']
    list_filter = ['is_accepted', 'is_rejected']
    search_fields = ['bidder__email', 'package__location']
    raw_id_fields = ['package', 'bidder']


@admin.register(PackageOffer)
class PackageOfferAdmin(admin.ModelAdmin):
    list_display = ['id', 'package', 'driver', 'agreed_amount', 'picked_up', 'delivered', 'is_cancelled', 'created_at']
    list_filter = ['picked_up', 'delivered', 'is_cancelled']
    search_fields = ['driver__email', 'package__location']
    raw_id_fields = ['package', 'bid', 'driver']


@admin.register(QRCode)
class QRCodeAdmin(admin.ModelAdmin):
    list_display = ['id', 'package', 'code', 'is_scanned', 'scanned_at']
    list_filter = ['is_scanned']
    search_fields = ['code', 'package__id']
    raw_id_fields = ['package']