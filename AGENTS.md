# AGENTS.md

This file contains guidelines for agentic coding agents working in the Movr Django project.

## Project Overview

Movr is a Django-based transportation and logistics platform with OTP-based authentication, KYC verification, vehicle management, route scheduling, package delivery with bidding, wallet integration (Paystack/Monnify), and WebSocket notifications.

## Build Commands

### Development Server
```bash
python manage.py runserver
```

### Database
```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
python manage.py seed_data
```

### Testing
```bash
python manage.py test                              # All tests
python manage.py test Api                         # Specific app
python manage.py test Api.tests.test_views         # Test file
python manage.py test Api.tests.test_views.RegisterViewTestCase.test_successful_registration  # Single test
pytest -q                                         # With pytest
pytest -k test_name                               # By pattern
```

### Code Quality
```bash
flake8 .  # If installed
black .   # If installed
```

## Code Style

### Import Order
```python
# Standard library
import os
from datetime import datetime, timedelta

# Third-party
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.response import Response

# Local
from Api.models import CustomUser, KYC
from wallet.services import create_dedicated_account
```

### Models
- Use `UUIDModel` as base class (provides UUID pk, created_at, updated_at)
- Use `verbose_name`, `verbose_name_plural`, and `help_text` on all fields
- Default ordering: `ordering = ['-created_at']`

### Views
- Use `TokenAuthentication`
- Include docstrings for all classes/methods
- Use `get_user_from_token(request)` for authentication
- Return consistent response format with proper HTTP status codes

### Naming
- Models/Views/Serializers: PascalCase (e.g., `Wallet`, `RegisterView`)
- Functions/Variables: snake_case (e.g., `get_user_from_token`)
- Constants: UPPER_SNAKE_CASE
- URL patterns: kebab-case (`/api/register/`)

### Error Handling
- Use proper status codes (400, 401, 403, 404, 500)
- Return descriptive error messages
- Handle database exceptions gracefully

### File Organization
```
Api/         - models.py, views.py, serializers.py, urls.py, tests/
wallet/      - models.py, views.py, serializers.py, services.py, utils.py
```

## Environment Variables
```bash
SECRET_KEY, DEBUG, ALLOWED_HOSTS, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD
MONNIFY_SANDBOX, MONNIFY_API_KEY, MONNIFY_SECRET_KEY, MONNIFY_CONTRACT_CODE
```

## Dependencies
Django 5.1.1, Django REST Framework, Django Channels, drf-spectacular, python-decouple, Pillow

## Security
- Token-based auth
- CORS enabled for dev only
- Rate limiting on sensitive endpoints
- Validate file uploads (type, size)

## API Docs
Swagger/OpenAPI available at `/api/docs/` when running

## Common Patterns

**Authentication:**
```python
def get_user_from_token(request):
    try:
        token = request.headers.get('Authorization', '').split(' ')[1]
        token = Token.objects.get(key=token)
        return token.user
    except Exception:
        raise AuthenticationFailed('Invalid token')
```

**Response Format:**
```python
return Response({'message': 'Success', 'data': serialized_data}, status=status.HTTP_200_OK)
return Response({'error': 'Error message'}, status=status.HTTP_400_BAD_REQUEST)
```
