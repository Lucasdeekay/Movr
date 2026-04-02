from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from drf_spectacular.utils import extend_schema
from django.utils import timezone

from Api.views import get_user_from_token
from .models import EmergencySOS
from .serializers import EmergencySOSSerializer


class TriggerSOSView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(request=EmergencySOSSerializer, responses={201: EmergencySOSSerializer}, tags=['Emergency'])
    def post(self, request):
        user = get_user_from_token(request)
        serializer = EmergencySOSSerializer(data=request.data)
        if serializer.is_valid():
            sos = serializer.save(user=user)
            
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                "sos_alerts",
                {"type": "sos_alert", "alert": {"id": str(sos.id), "user": user.email, "status": sos.status}}
            )
            return Response(EmergencySOSSerializer(sos).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetSOSAlertsView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: EmergencySOSSerializer(many=True)}, tags=['Emergency'])
    def get(self, request):
        user = get_user_from_token(request)
        if user.is_staff:
            alerts = EmergencySOS.objects.all().select_related('user', 'acknowledged_by')
        else:
            alerts = EmergencySOS.objects.filter(user=user).select_related('user')
        return Response(EmergencySOSSerializer(alerts, many=True).data, status=status.HTTP_200_OK)


class AcknowledgeSOSView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(request=EmergencySOSSerializer, responses={200: EmergencySOSSerializer}, tags=['Emergency'])
    def post(self, request, sos_id):
        user = get_user_from_token(request)
        if not user.is_staff:
            return Response({'error': 'Admin only'}, status=status.HTTP_403_FORBIDDEN)
        try:
            sos = EmergencySOS.objects.get(id=sos_id)
            sos.status = 'acknowledged'
            sos.acknowledged_by = user
            sos.save()
            return Response(EmergencySOSSerializer(sos).data, status=status.HTTP_200_OK)
        except EmergencySOS.DoesNotExist:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)


class ResolveSOSView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(request=EmergencySOSSerializer, responses={200: EmergencySOSSerializer}, tags=['Emergency'])
    def post(self, request, sos_id):
        user = get_user_from_token(request)
        if not user.is_staff:
            return Response({'error': 'Admin only'}, status=status.HTTP_403_FORBIDDEN)
        try:
            sos = EmergencySOS.objects.get(id=sos_id)
            sos.status = 'resolved'
            sos.resolved_at = timezone.now()
            sos.save()
            return Response(EmergencySOSSerializer(sos).data, status=status.HTTP_200_OK)
        except EmergencySOS.DoesNotExist:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)