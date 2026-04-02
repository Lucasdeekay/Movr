from django.urls import path
from .views import UpdatePresenceView, GetOnlineUsersView, GetUserLocationView

urlpatterns = [
    path('update/', UpdatePresenceView.as_view(), name='update-presence'),
    path('online/', GetOnlineUsersView.as_view(), name='online-users'),
    path('user/<uuid:user_id>/', GetUserLocationView.as_view(), name='user-location'),
]