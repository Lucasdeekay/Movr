from django.urls import path
from .views import SendChatMessageView, GetConversationMessagesView, GetUserConversationsView, CreateConversationView

urlpatterns = [
    path('send/', SendChatMessageView.as_view(), name='send-message'),
    path('<uuid:conversation_id>/', GetConversationMessagesView.as_view(), name='get-messages'),
    path('conversations/', GetUserConversationsView.as_view(), name='get-conversations'),
    path('create/', CreateConversationView.as_view(), name='create-conversation'),
]