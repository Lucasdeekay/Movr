from django.urls import path
from .views import (
    CreateRouteView, CreateScheduledRouteView, UserRoutesView,
    ToggleIsLiveRouteView, GetScheduledRoutesView, GetLiveRoutesCountView,
    DaysListView
)

urlpatterns = [
    path('create-route/', CreateRouteView.as_view(), name='create-route'),
    path('create-scheduled-route/', CreateScheduledRouteView.as_view(), name='create-scheduled-route'),
    path('user-routes/', UserRoutesView.as_view(), name='user-routes'),
    path('toggle-is-live/<uuid:route_id>/', ToggleIsLiveRouteView.as_view(), name='toggle-is-live'),
    path('scheduled-routes/', GetScheduledRoutesView.as_view(), name='scheduled-routes'),
    path('live-routes-count/', GetLiveRoutesCountView.as_view(), name='live-routes-count'),
    path('days/', DaysListView.as_view(), name='days-list'),
]