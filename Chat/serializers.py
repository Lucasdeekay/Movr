from rest_framework import serializers
from .models import ChatConversation, ChatMessage


class ChatConversationSerializer(serializers.ModelSerializer):
    participant_emails = serializers.SerializerMethodField()
    
    class Meta:
        model = ChatConversation
        fields = ['id', 'participants', 'participant_emails', 'trip', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_participant_emails(self, obj):
        return [u.email for u in obj.participants.all()]


class ChatMessageSerializer(serializers.ModelSerializer):
    sender_email = serializers.ReadOnlyField(source='sender.email')
    
    class Meta:
        model = ChatMessage
        fields = ['id', 'conversation', 'sender', 'sender_email', 'message', 'is_read', 'read_at', 'created_at']
        read_only_fields = ['id', 'created_at']