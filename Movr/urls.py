"""
URL configuration for Movr project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework.documentation import include_docs_urls
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)

urlpatterns = [
    path('manager/', admin.site.urls),
    
    # Auth API v1
    path('auth/v1/', include('Auth.urls')),
    
    # Profile API v1
    path('profile/v1/', include('Profile.urls')),
    
    # Other apps (keep existing for now, can add versioning later)
    path('wallet/', include('wallet.urls')),
    path('routes/', include('Routes.urls')),
    path('packages/', include('Packages.urls')),
    path('chat/', include('Chat.urls')),
    path('presence/', include('Presence.urls')),
    path('emergency/', include('Emergency.urls')),
    
    # API Schema
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]