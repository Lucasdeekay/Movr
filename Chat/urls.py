from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .models import ChatConversation, ChatMessage
from .serializers import ChatConversationSerializer, ChatMessageSerializer
from rest_framework import viewsets
from .views import SendChatMessageView, GetConversationMessagesView, GetUserConversationsView, CreateConversationView


class ChatConversationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for ChatConversation CRUD operations.
    
    Provides endpoints for:
    - GET /conversations/ - List all conversations
    - POST /conversations/ - Create new conversation
    - GET /conversations/{id}/ - Retrieve conversation
    - PUT /conversations/{id}/ - Update conversation
    - DELETE /conversations/{id}/ - Delete conversation
    """
    queryset = ChatConversation.objects.all()
    serializer_class = ChatConversationSerializer


class ChatMessageViewSet(viewsets.ModelViewSet):
    """
    ViewSet for ChatMessage CRUD operations.
    
    Provides endpoints for:
    - GET /messages/ - List all messages
    - POST /messages/ - Create new message
    - GET /messages/{id}/ - Retrieve message
    - PUT /messages/{id}/ - Update message
    - DELETE /messages/{id}/ - Delete message
    """
    queryset = ChatMessage.objects.all()
    serializer_class = ChatMessageSerializer


router = DefaultRouter()
router.register(r'conversations', ChatConversationViewSet, basename='chat-conversation')
router.register(r'messages', ChatMessageViewSet, basename='chat-message')

urlpatterns = [
    path('send/', SendChatMessageView.as_view(), name='send-message'),
    path('<uuid:conversation_id>/', GetConversationMessagesView.as_view(), name='get-messages'),
    path('conversations/', GetUserConversationsView.as_view(), name='get-conversations'),
    path('create/', CreateConversationView.as_view(), name='create-conversation'),
    path('api/', include(router.urls)),
]