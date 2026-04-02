from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .models import Route, ScheduledRoute, Day
from .serializers import RouteSerializer, ScheduledRouteSerializer, DaySerializer
from rest_framework import viewsets
from drf_spectacular.utils import extend_schema, OpenApiExample
from .views import (
    CreateRouteView, CreateScheduledRouteView, UserRoutesView,
    ToggleIsLiveRouteView, GetScheduledRoutesView, GetLiveRoutesCountView,
    DaysListView
)


class RouteViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Route CRUD operations.
    
    Provides endpoints for:
    - GET /routes/ - List all routes
    - POST /routes/ - Create new route
    - GET /routes/{id}/ - Retrieve route
    - PUT /routes/{id}/ - Update route
    - DELETE /routes/{id}/ - Delete route
    """
    queryset = Route.objects.all()
    serializer_class = RouteSerializer


class ScheduledRouteViewSet(viewsets.ModelViewSet):
    """
    ViewSet for ScheduledRoute CRUD operations.
    
    Provides endpoints for:
    - GET /scheduled-routes/ - List all scheduled routes
    - POST /scheduled-routes/ - Create new scheduled route
    - GET /scheduled-routes/{id}/ - Retrieve scheduled route
    - PUT /scheduled-routes/{id}/ - Update scheduled route
    - DELETE /scheduled-routes/{id}/ - Delete scheduled route
    """
    queryset = ScheduledRoute.objects.all()
    serializer_class = ScheduledRouteSerializer


class DayViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Day CRUD operations.
    
    Provides endpoints for:
    - GET /days/ - List all days
    - POST /days/ - Create new day
    - GET /days/{id}/ - Retrieve day
    - PUT /days/{id}/ - Update day
    - DELETE /days/{id}/ - Delete day
    """
    queryset = Day.objects.all()
    serializer_class = DaySerializer


router = DefaultRouter()
router.register(r'routes', RouteViewSet, basename='route')
router.register(r'scheduled-routes', ScheduledRouteViewSet, basename='scheduled-route')
router.register(r'days', DayViewSet, basename='day')

urlpatterns = [
    path('create-route/', CreateRouteView.as_view(), name='create-route'),
    path('create-scheduled-route/', CreateScheduledRouteView.as_view(), name='create-scheduled-route'),
    path('user-routes/', UserRoutesView.as_view(), name='user-routes'),
    path('toggle-is-live/<uuid:route_id>/', ToggleIsLiveRouteView.as_view(), name='toggle-is-live'),
    path('scheduled-routes/', GetScheduledRoutesView.as_view(), name='scheduled-routes'),
    path('live-routes-count/', GetLiveRoutesCountView.as_view(), name='live-routes-count'),
    path('days/', DaysListView.as_view(), name='days-list'),
    path('api/', include(router.urls)),
]