from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .viewsets import (
    CustomUserViewSet, KYCViewSet, VehicleViewSet,
    PaymentMethodViewSet, SubscriptionPlanViewSet,
    SubscriptionViewSet, OTPViewSet, SocialMediaLinkViewSet, RouteViewSet, ScheduledRouteViewSet, DayViewSet
)
from .views import (
    RegisterView,
    VerifyOTPView,
    LoginView,
    LogoutView,
    ForgotPasswordRequestOTPView,
    ResetPasswordView, UpdateKYCView, UpdateVehicleInfoView, UpdatePersonalInfoView, UpdateSubscriptionPlanView,
    CreateRouteView, CreateScheduledRouteView, UserRoutesView, ToggleIsLiveRouteView, PackageSubmissionView,
    PlaceBidView, PickupConfirmationView, DeliveryConfirmationView, SelectMoverView, GetAllBidsView, GetBidDetailView,
    GetPackageOfferDetailView, ResendOTPView
)

# Initialize the router
router = DefaultRouter()

# Register the viewsets with the router
router.register(r'users', CustomUserViewSet, basename='user')
router.register(r'kyc', KYCViewSet, basename='kyc')
router.register(r'social-media-links', SocialMediaLinkViewSet, basename='social-media-link')
router.register(r'vehicles', VehicleViewSet, basename='vehicle')
router.register(r'payment-methods', PaymentMethodViewSet, basename='payment-method')
router.register(r'subscription-plans', SubscriptionPlanViewSet, basename='subscription-plan')
router.register(r'subscriptions', SubscriptionViewSet, basename='subscription')
router.register(r'otps', OTPViewSet, basename='otp')
router.register(r'routes', RouteViewSet, basename='route')
router.register(r'scheduled-routes', ScheduledRouteViewSet, basename='scheduled-route')
router.register(r'days', DayViewSet, basename='day')

# Include the router in your URL patterns
urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp', ResendOTPView.as_view(), name='resend-otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('forgot-password/', ForgotPasswordRequestOTPView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('update-kyc/', UpdateKYCView.as_view(), name='update-kyc'),
    path('update-vehicle/', UpdateVehicleInfoView.as_view(), name='update-vehicle'),
    path('update-personal-info/', UpdatePersonalInfoView.as_view(), name='update-personal-info'),
    path('update-subscription/', UpdateSubscriptionPlanView.as_view(), name='update-subscription'),
    path('create-route/', CreateRouteView.as_view(), name='create-route'),
    path('create-scheduled-route/', CreateScheduledRouteView.as_view(), name='create-scheduled-route'),
    path('user-routes/', UserRoutesView.as_view(), name='user-routes'),
    path('toggle-is-live/<int:route_id>/', ToggleIsLiveRouteView.as_view(), name='toggle-is-live'),
    path('submit-package/', PackageSubmissionView.as_view(), name='submit-package'),
    path('place-bid/<int:package_id>/', PlaceBidView.as_view(), name='place-bid'),
    path('package/<int:package_id>/bids/', GetAllBidsView.as_view(), name='get-all-bids'),
    path('bid/<int:bid_id>/', GetBidDetailView.as_view(), name='get-bid-detail'),
    path('select-mover/<int:bid_id>/', SelectMoverView.as_view(), name='select-mover'),
    path('confirm-pickup/<int:package_offer_id>/', PickupConfirmationView.as_view(), name='confirm-pickup'),
    path('confirm-delivery/<int:package_offer_id>/', DeliveryConfirmationView.as_view(), name='confirm-delivery'),
    path('package-offer/<int:package_offer_id>/', GetPackageOfferDetailView.as_view(), name='get-package-offer-detail'),
    path('api/', include(router.urls)),
]
