from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from drf_spectacular.utils import extend_schema, OpenApiExample
from django.utils import timezone

from Api.models import CustomUser
from Api.views import get_user_from_token
from .models import Route, ScheduledRoute, Day
from .serializers import RouteSerializer, ScheduledRouteSerializer, DaySerializer


class CreateRouteView(APIView):
    """
    API view for creating a new route.
    
    Allows authenticated users to create a new route by providing
    the necessary details such as location, destination, transportation mode,
    and departure time.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=RouteSerializer,
        responses={201: RouteSerializer, 400: dict},
        tags=['Routes'],
        examples=[
            OpenApiExample(
                'Create Route',
                value={
                    'location': 'Lagos',
                    'location_latitude': '6.5244',
                    'location_longitude': '3.3792',
                    'destination': 'Abuja',
                    'destination_latitude': '9.0765',
                    'destination_longitude': '7.3986',
                    'transportation_mode': 'car',
                    'departure_time': '2024-01-15T08:00:00Z',
                    'service_type': 'ride'
                },
                request_only=True,
            ),
        ],
    )
    def post(self, request):
        user = get_user_from_token(request)
        serializer = RouteSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CreateScheduledRouteView(APIView):
    """
    API view for creating a scheduled recurring route.
    
    Allows authenticated users to create a scheduled route that repeats
    on specific days of the week.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=ScheduledRouteSerializer,
        responses={201: ScheduledRouteSerializer, 400: dict},
        tags=['Routes'],
    )
    def post(self, request):
        user = get_user_from_token(request)
        serializer = ScheduledRouteSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserRoutesView(APIView):
    """
    API view for getting all routes for the authenticated user.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: RouteSerializer(many=True)},
        tags=['Routes'],
    )
    def get(self, request):
        user = get_user_from_token(request)
        routes = Route.objects.filter(user=user)
        serializer = RouteSerializer(routes, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ToggleIsLiveRouteView(APIView):
    """
    API view for toggling the live status of a route.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: dict, 404: dict},
        tags=['Routes'],
    )
    def post(self, request, route_id):
        user = get_user_from_token(request)
        try:
            route = Route.objects.get(id=route_id, user=user)
        except Route.DoesNotExist:
            return Response({'error': 'Route not found'}, status=status.HTTP_404_NOT_FOUND)
        
        route.is_live = not route.is_live
        route.save()
        
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        channel_layer = get_channel_layer()
        
        async_to_sync(channel_layer.group_send)(
            f"user_{user.id}",
            {
                "type": "live_routes_count",
                "route_id": str(route.id),
                "is_live": route.is_live,
            }
        )
        
        return Response({
            'message': 'Route is_live field updated.',
            'is_live': route.is_live
        }, status=status.HTTP_200_OK)


class GetScheduledRoutesView(APIView):
    """
    API view for getting all scheduled routes.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: ScheduledRouteSerializer(many=True)},
        tags=['Routes'],
    )
    def get(self, request):
        user = get_user_from_token(request)
        scheduled_routes = ScheduledRoute.objects.filter(user=user, is_active=True)
        serializer = ScheduledRouteSerializer(scheduled_routes, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class GetLiveRoutesCountView(APIView):
    """
    API view for getting the count of live routes.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: dict},
        tags=['Routes'],
    )
    def get(self, request):
        user = get_user_from_token(request)
        count = Route.objects.filter(user=user, is_live=True).count()
        return Response({'live_routes_count': count}, status=status.HTTP_200_OK)


class DaysListView(APIView):
    """
    API view for listing all available days.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: DaySerializer(many=True)},
        tags=['Routes'],
    )
    def get(self, request):
        days = Day.objects.all()
        serializer = DaySerializer(days, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)