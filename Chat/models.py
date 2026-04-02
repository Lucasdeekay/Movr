from django.db import models
from Api.models import UUIDModel

class ChatConversation(UUIDModel):
    """Chat conversation between users, optionally linked to a trip."""
    participants = models.ManyToManyField('Api.CustomUser', related_name='conversations')
    trip = models.ForeignKey('Packages.PackageOffer', on_delete=models.CASCADE, null=True, blank=True, related_name='chat_conversations')
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Chat Conversation"
        verbose_name_plural = "Chat Conversations"

    def __str__(self):
        return f"Conversation {self.id}"


class ChatMessage(UUIDModel):
    """Individual messages in a conversation."""
    conversation = models.ForeignKey(ChatConversation, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey('Api.CustomUser', on_delete=models.CASCADE, related_name='sent_messages')
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Chat Message"
        verbose_name_plural = "Chat Messages"
        ordering = ['created_at']

    def __str__(self):
        return f"Message from {self.sender.email}"