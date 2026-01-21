from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .viewsets import (
    CustomUserViewSet, KYCViewSet, VehicleViewSet, SubscriptionPlanViewSet,
    SubscriptionViewSet, OTPViewSet, SocialMediaLinkViewSet, RouteViewSet, ScheduledRouteViewSet, DayViewSet,
    BadgeViewSet, UserBadgeViewSet, ReferralTokenViewSet, ReferralViewSet
)
from .views import (
    RegisterView,
    VerifyOTPView,
    LoginView,
    LogoutView,
    ForgotPasswordRequestOTPView,
    ResetPasswordView, UpdateKYCView, UpdateVehicleInfoView, UpdatePersonalInfoView, UpdateSubscriptionPlanView,
    ProfileImageUploadView, CreateRouteView, CreateScheduledRouteView, UserRoutesView, ToggleIsLiveRouteView, PackageSubmissionView,
    PlaceBidView, PickupConfirmationView, DeliveryConfirmationView, SelectMoverView, GetAllBidsView, GetBidDetailView,
    GetPackageOfferDetailView, ResendOTPView, PickedUpPackageOffersView, GetAllPackageOffersView,
    ScheduledPackageOffersView, CancelPackageOfferView,
    )

# Initialize the router
router = DefaultRouter()

# Register the viewsets with the router
router.register(r'users', CustomUserViewSet, basename='user')
router.register(r'kyc', KYCViewSet, basename='kyc')
router.register(r'social-media-links', SocialMediaLinkViewSet, basename='social-media-link')
router.register(r'vehicles', VehicleViewSet, basename='vehicle')
router.register(r'subscription-plans', SubscriptionPlanViewSet, basename='subscription-plan')
router.register(r'subscriptions', SubscriptionViewSet, basename='subscription')
router.register(r'otps', OTPViewSet, basename='otp')
router.register(r'routes', RouteViewSet, basename='route')
router.register(r'scheduled-routes', ScheduledRouteViewSet, basename='scheduled-route')
router.register(r'days', DayViewSet, basename='day')
router.register(r'badges', BadgeViewSet, basename='badge')
router.register(r'user-badges', UserBadgeViewSet, basename='userbadge')
router.register(r'referral-tokens', ReferralTokenViewSet, basename='referral-token')
router.register(r'referrals', ReferralViewSet, basename='referral')

# Include the router in your URL patterns
urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('forgot-password/', ForgotPasswordRequestOTPView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('update-kyc/', UpdateKYCView.as_view(), name='update-kyc'),
    path('update-vehicle/', UpdateVehicleInfoView.as_view(), name='update-vehicle'),
    path('update-personal-info/', UpdatePersonalInfoView.as_view(), name='update-personal-info'),
    path('upload-profile-image/', ProfileImageUploadView.as_view(), name='upload-profile-image'),
    path('update-subscription/', UpdateSubscriptionPlanView.as_view(), name='update-subscription'),
    path('create-route/', CreateRouteView.as_view(), name='create-route'),
    path('create-scheduled-route/', CreateScheduledRouteView.as_view(), name='create-scheduled-route'),
    path('user-routes/', UserRoutesView.as_view(), name='user-routes'),
    path('toggle-is-live/<uuid:route_id>/', ToggleIsLiveRouteView.as_view(), name='toggle-is-live'),
    path('submit-package/', PackageSubmissionView.as_view(), name='submit-package'),
    path('place-bid/<uuid:package_id>/', PlaceBidView.as_view(), name='place-bid'),
    path('package/<uuid:package_id>/bids/', GetAllBidsView.as_view(), name='get-all-bids'),
    path('bid/<uuid:bid_id>/', GetBidDetailView.as_view(), name='get-bid-detail'),
    path('select-mover/<uuid:bid_id>/', SelectMoverView.as_view(), name='select-mover'),
    path('package-offers/', GetAllPackageOffersView.as_view(), name='get-all-package-offers'),
    path('package-offer/<uuid:package_offer_id>/', GetPackageOfferDetailView.as_view(), name='get-package-offer-detail'),
    path('confirm-pickup/<uuid:package_offer_id>/', PickupConfirmationView.as_view(), name='confirm-pickup'),
    path('confirm-delivery/<uuid:package_offer_id>/', DeliveryConfirmationView.as_view(), name='confirm-delivery'),
    path('offers/picked-up/', PickedUpPackageOffersView.as_view(), name='picked-up-package-offers'),
    path('offers/scheduled/', ScheduledPackageOffersView.as_view(), name='scheduled-package-offers'),
    path('offers/<uuid:pk>/cancel/', CancelPackageOfferView.as_view(), name='cancel-package-offer'),
    path('api/', include(router.urls)),
]
