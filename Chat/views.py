from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from drf_spectacular.utils import extend_schema

from Api.views import get_user_from_token
from .models import ChatConversation, ChatMessage
from .serializers import ChatConversationSerializer, ChatMessageSerializer


class SendChatMessageView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(request=ChatMessageSerializer, responses={201: ChatMessageSerializer}, tags=['Chat'])
    def post(self, request):
        user = get_user_from_token(request)
        serializer = ChatMessageSerializer(data=request.data)
        if serializer.is_valid():
            conversation = serializer.validated_data['conversation']
            if user not in conversation.participants.all():
                return Response({'error': 'Not a participant'}, status=status.HTTP_403_FORBIDDEN)
            message = serializer.save(sender=user)
            
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            channel_layer = get_channel_layer()
            for participant in conversation.participants.all():
                async_to_sync(channel_layer.group_send)(
                    f"user_{participant.id}",
                    {"type": "chat_message", "message": {"id": str(message.id), "sender": user.email, "message": message.message}}
                )
            return Response(ChatMessageSerializer(message).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetConversationMessagesView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: ChatMessageSerializer(many=True)}, tags=['Chat'])
    def get(self, request, conversation_id):
        user = get_user_from_token(request)
        try:
            conversation = ChatConversation.objects.get(id=conversation_id)
        except ChatConversation.DoesNotExist:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        if user not in conversation.participants.all():
            return Response({'error': 'Not a participant'}, status=status.HTTP_403_FORBIDDEN)
        messages = conversation.messages.all()
        return Response(ChatMessageSerializer(messages, many=True).data, status=status.HTTP_200_OK)


class GetUserConversationsView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: ChatConversationSerializer(many=True)}, tags=['Chat'])
    def get(self, request):
        user = get_user_from_token(request)
        conversations = ChatConversation.objects.filter(participants=user, is_active=True)
        return Response(ChatConversationSerializer(conversations, many=True).data, status=status.HTTP_200_OK)


class CreateConversationView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(request=ChatConversationSerializer, responses={201: ChatConversationSerializer}, tags=['Chat'])
    def post(self, request):
        user = get_user_from_token(request)
        serializer = ChatConversationSerializer(data=request.data)
        if serializer.is_valid():
            conversation = serializer.save()
            conversation.participants.add(user)
            return Response(ChatConversationSerializer(conversation).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)