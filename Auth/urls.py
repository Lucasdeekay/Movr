from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .models import CustomUser
from .serializers import CustomUserSerializer
from rest_framework import viewsets
from .views import (
    RegisterView, VerifyOTPView, ResendOTPView, LoginView, LogoutView,
    ForgotPasswordRequestOTPView, ResetPasswordView, get_user_from_token
)
from drf_spectacular.utils import extend_schema, OpenApiExample


class CustomUserViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing CustomUser CRUD operations.
    
    Provides endpoints for:
    - GET /users/ - List all users
    - POST /users/ - Create new user
    - GET /users/{id}/ - Retrieve user
    - PUT /users/{id}/ - Update user
    - DELETE /users/{id}/ - Delete user
    """
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer


router = DefaultRouter()
router.register(r'users', CustomUserViewSet, basename='user')

urlpatterns = [
    # Authentication endpoints
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('forgot-password/', ForgotPasswordRequestOTPView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    
    # User management endpoints
    path('api/', include(router.urls)),
]