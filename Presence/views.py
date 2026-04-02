from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from drf_spectacular.utils import extend_schema

from Api.views import get_user_from_token
from .models import UserPresence
from .serializers import UserPresenceSerializer
from django.utils import timezone


class UpdatePresenceView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(request=UserPresenceSerializer, responses={200: UserPresenceSerializer}, tags=['Presence'])
    def post(self, request):
        user = get_user_from_token(request)
        presence, _ = UserPresence.objects.get_or_create(user=user)
        serializer = UserPresenceSerializer(presence, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetOnlineUsersView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: UserPresenceSerializer(many=True)}, tags=['Presence'])
    def get(self, request):
        users = UserPresence.objects.filter(is_online=True).select_related('user')
        return Response(UserPresenceSerializer(users, many=True).data, status=status.HTTP_200_OK)


class GetUserLocationView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: UserPresenceSerializer}, tags=['Presence'])
    def get(self, request, user_id):
        try:
            presence = UserPresence.objects.select_related('user').get(user_id=user_id)
            return Response(UserPresenceSerializer(presence).data, status=status.HTTP_200_OK)
        except UserPresence.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)