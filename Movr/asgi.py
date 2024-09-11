"""
ASGI config for Movr project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

import os

from channels.auth import AuthMiddlewareStack
from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from channels.routing import ProtocolTypeRouter, URLRouter
from django.contrib.auth.models import AnonymousUser
from django.core.asgi import get_asgi_application
from django.db import close_old_connections
from rest_framework.authtoken.models import Token

import Api


class TokenAuthMiddleware(BaseMiddleware):
    """
    Custom token-based authentication middleware
    """

    async def __call__(self, scope, receive, send):
        headers = dict(scope['headers'])
        token_key = headers.get(b'sec-websocket-protocol', None)

        if token_key:
            try:
                token_name, token_value = token_key.decode().split(',')
                token = await database_sync_to_async(Token.objects.get)(key=token_value)
                scope['user'] = token.user
            except Token.DoesNotExist:
                scope['user'] = AnonymousUser()

        close_old_connections()
        return await super().__call__(scope, receive, send)


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Movr.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": TokenAuthMiddleware(
        AuthMiddlewareStack(
            URLRouter(
                Api.routing.websocket_urlpatterns
            )
        )
    ),
})
