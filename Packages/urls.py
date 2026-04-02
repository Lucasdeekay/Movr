from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .models import Package, Bid, PackageOffer, QRCode
from .serializers import PackageSerializer, BidSerializer, PackageOfferSerializer, QRCodeSerializer
from rest_framework import viewsets
from .views import (
    PackageSubmissionView, PlaceBidView, GetAllBidsView, GetBidDetailView,
    SelectMoverView, GetAllPackageOffersView, GetPackageOfferDetailView,
    PickupConfirmationView, DeliveryConfirmationView, PickedUpPackageOffersView,
    ScheduledPackageOffersView, CancelPackageOfferView
)


class PackageViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Package CRUD operations.
    
    Provides endpoints for:
    - GET /packages/ - List all packages
    - POST /packages/ - Create new package
    - GET /packages/{id}/ - Retrieve package
    - PUT /packages/{id}/ - Update package
    - DELETE /packages/{id}/ - Delete package
    """
    queryset = Package.objects.all()
    serializer_class = PackageSerializer


class BidViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Bid CRUD operations.
    
    Provides endpoints for:
    - GET /bids/ - List all bids
    - POST /bids/ - Create new bid
    - GET /bids/{id}/ - Retrieve bid
    - PUT /bids/{id}/ - Update bid
    - DELETE /bids/{id}/ - Delete bid
    """
    queryset = Bid.objects.all()
    serializer_class = BidSerializer


class PackageOfferViewSet(viewsets.ModelViewSet):
    """
    ViewSet for PackageOffer CRUD operations.
    
    Provides endpoints for:
    - GET /offers/ - List all offers
    - POST /offers/ - Create new offer
    - GET /offers/{id}/ - Retrieve offer
    - PUT /offers/{id}/ - Update offer
    - DELETE /offers/{id}/ - Delete offer
    """
    queryset = PackageOffer.objects.all()
    serializer_class = PackageOfferSerializer


class QRCodeViewSet(viewsets.ModelViewSet):
    """
    ViewSet for QRCode CRUD operations.
    
    Provides endpoints for:
    - GET /qrcodes/ - List all QR codes
    - POST /qrcodes/ - Create new QR code
    - GET /qrcodes/{id}/ - Retrieve QR code
    - PUT /qrcodes/{id}/ - Update QR code
    - DELETE /qrcodes/{id}/ - Delete QR code
    """
    queryset = QRCode.objects.all()
    serializer_class = QRCodeSerializer


router = DefaultRouter()
router.register(r'packages', PackageViewSet, basename='package')
router.register(r'bids', BidViewSet, basename='bid')
router.register(r'offers', PackageOfferViewSet, basename='package-offer')
router.register(r'qrcodes', QRCodeViewSet, basename='qrcode')

urlpatterns = [
    path('submit-package/', PackageSubmissionView.as_view(), name='submit-package'),
    path('place-bid/<uuid:package_id>/', PlaceBidView.as_view(), name='place-bid'),
    path('package/<uuid:package_id>/bids/', GetAllBidsView.as_view(), name='get-all-bids'),
    path('bid/<uuid:bid_id>/', GetBidDetailView.as_view(), name='get-bid-detail'),
    path('select-mover/<uuid:bid_id>/', SelectMoverView.as_view(), name='select-mover'),
    path('package-offers/', GetAllPackageOffersView.as_view(), name='get-all-package-offers'),
    path('package-offer/<uuid:package_offer_id>/', GetPackageOfferDetailView.as_view(), name='get-package-offer-detail'),
    path('confirm-pickup/<uuid:package_offer_id>/', PickupConfirmationView.as_view(), name='confirm-pickup'),
    path('confirm-delivery/<uuid:package_offer_id>/', DeliveryConfirmationView.as_view(), name='confirm-delivery'),
    path('offers/picked-up/', PickedUpPackageOffersView.as_view(), name='picked-up-offers'),
    path('offers/scheduled/', ScheduledPackageOffersView.as_view(), name='scheduled-offers'),
    path('offers/<uuid:pk>/cancel/', CancelPackageOfferView.as_view(), name='cancel-offer'),
    path('api/', include(router.urls)),
]