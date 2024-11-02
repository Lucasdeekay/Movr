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
    CreateRouteView, CreateScheduledRouteView, UserRoutesView, ToggleIsLiveRouteView
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
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('forgot-password/', ForgotPasswordRequestOTPView.as_view(), name='forgot_password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset_password'),
    path('update-kyc/', UpdateKYCView.as_view(), name='update_kyc'),
    path('update-vehicle/', UpdateVehicleInfoView.as_view(), name='update_vehicle'),
    path('update-personal-info/', UpdatePersonalInfoView.as_view(), name='update_personal_info'),
    path('update-subscription/', UpdateSubscriptionPlanView.as_view(), name='update_subscription'),
    path('create-route/', CreateRouteView.as_view(), name='create-route'),
    path('create-scheduled-route/', CreateScheduledRouteView.as_view(), name='create-scheduled-route'),
    path('user-routes/', UserRoutesView.as_view(), name='user-routes'),
    path('toggle-is-live/<int:route_id>/', ToggleIsLiveRouteView.as_view(), name='toggle-is-live'),
    path('api/', include(router.urls)),
]
