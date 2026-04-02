from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .models import UserPresence
from .serializers import UserPresenceSerializer
from rest_framework import viewsets
from .views import UpdatePresenceView, GetOnlineUsersView, GetUserLocationView


class UserPresenceViewSet(viewsets.ModelViewSet):
    """
    ViewSet for UserPresence CRUD operations.
    
    Provides endpoints for:
    - GET /presences/ - List all user presences
    - POST /presences/ - Create new presence
    - GET /presences/{id}/ - Retrieve presence
    - PUT /presences/{id}/ - Update presence
    - DELETE /presences/{id}/ - Delete presence
    """
    queryset = UserPresence.objects.all()
    serializer_class = UserPresenceSerializer


router = DefaultRouter()
router.register(r'presences', UserPresenceViewSet, basename='user-presence')

urlpatterns = [
    path('update/', UpdatePresenceView.as_view(), name='update-presence'),
    path('online/', GetOnlineUsersView.as_view(), name='online-users'),
    path('user/<uuid:user_id>/', GetUserLocationView.as_view(), name='user-location'),
    path('api/', include(router.urls)),
]