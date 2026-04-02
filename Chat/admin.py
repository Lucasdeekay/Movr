from django.contrib import admin
from .models import ChatConversation, ChatMessage

@admin.register(ChatConversation)
class ChatConversationAdmin(admin.ModelAdmin):
    list_display = ['id', 'is_active', 'created_at']
    filter_horizontal = ['participants']

@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ['id', 'conversation', 'sender', 'is_read', 'created_at']
    list_filter = ['is_read']