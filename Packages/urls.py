from django.urls import path
from django.db import models
from .views import (
    PackageSubmissionView, PlaceBidView, GetAllBidsView, GetBidDetailView,
    SelectMoverView, GetAllPackageOffersView, GetPackageOfferDetailView,
    PickupConfirmationView, DeliveryConfirmationView, PickedUpPackageOffersView,
    ScheduledPackageOffersView, CancelPackageOfferView
)

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
]