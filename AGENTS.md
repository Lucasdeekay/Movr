# AGENTS.md

This file contains guidelines and commands for agentic coding agents working in the Movr Django project.

## Project Overview

Movr is a Django-based transportation and logistics platform with the following key features:
- User authentication and verification (OTP-based)
- KYC (Know Your Customer) verification
- Vehicle registration and management
- Route creation and scheduling
- Package delivery and bidding system
- Wallet integration with Paystack and Monnify
- Real-time notifications via WebSocket (Channels)

## Build Commands

### Development Server
```bash
python manage.py runserver
```

### Database Management
```bash
# Create and apply migrations
python manage.py makemigrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Seed data (custom command)
python manage.py seed_data
```

### Testing
```bash
# Run all tests
python manage.py test

# Run specific app tests
python manage.py test Api
python manage.py test wallet

# Run specific test file
python manage.py test Api.tests.test_views
python manage.py test wallet.test.test_monnify_service

# Run with pytest (preferred)
pytest -q
pytest tests/  # If using pytest-django
```

### Code Quality
```bash
# No specific linting commands found in project
# Use standard Django/Python tools:
flake8 .  # If installed
black .   # If installed
```

## Code Style Guidelines

### Import Organization
```python
# Standard library imports first
import os
import uuid
from datetime import datetime, timedelta

# Third-party imports
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

# Local imports
from Api.models import CustomUser, KYC
from wallet.services import create_dedicated_account_for_user
```

### Model Conventions
- Use `UUIDModel` as base class for all models (provides UUID primary key)
- Include `created_at` and `updated_at` fields via inheritance
- Use descriptive `verbose_name` and `verbose_name_plural` in Meta class
- Order by `'-created_at'` by default
- Use `help_text` for all model fields

Example:
```python
class Wallet(UUIDModel):
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE, 
        related_name="wallet",
        help_text="User account associated with this wallet"
    )
    balance = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=0.00,
        validators=[MinValueValidator(0.00)],
        help_text="Current wallet balance"
    )
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Wallet"
        verbose_name_plural = "Wallets"
```

### View/Serializer Conventions
- Use TokenAuthentication for API views
- Include comprehensive docstrings for all classes and methods
- Use `get_user_from_token(request)` helper for authentication
- Return consistent response format with proper HTTP status codes
- Validate file uploads (type, size) in views

Example:
```python
class UpdateKYCView(APIView):
    """
    API view for updating the user's KYC (Know Your Customer) information.
    
    This view allows authenticated users to update their KYC details.
    """
    
    authentication_classes = [TokenAuthentication]
    
    def post(self, request, *args, **kwargs):
        """
        Handle POST requests for updating KYC information.
        
        Args:
            request: The HTTP request object containing the KYC data
            
        Returns:
            Response: A Response object indicating the result of the KYC update
        """
        user = get_user_from_token(request)
        # ... implementation
```

### Error Handling
- Use proper HTTP status codes (400, 401, 403, 404, 500)
- Return descriptive error messages in response data
- Validate input data and provide clear validation errors
- Handle database exceptions gracefully

Example:
```python
try:
    user = CustomUser.objects.get(email=email)
except CustomUser.DoesNotExist:
    return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
```

### Testing Conventions
- Use Django's `TestCase` or `APITestCase` for API tests
- Use descriptive test method names (`test_successful_registration`)
- Include comprehensive setup and teardown methods
- Test both success and failure scenarios
- Use factories/fixtures for test data

Example:
```python
class RegisterViewTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('register')
        self.free_plan = SubscriptionPlan.objects.create(name="free")
        
    def test_successful_registration(self):
        data = {"email": "newuser@example.com", "password": "password123"}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
```

### Naming Conventions
- **Models**: PascalCase (e.g., `CustomUser`, `Wallet`)
- **Views**: PascalCase with "View" suffix (e.g., `RegisterView`, `UpdateKYCView`)
- **Serializers**: PascalCase with "Serializer" suffix (e.g., `CustomUserSerializer`)
- **Variables/Functions**: snake_case (e.g., `get_user_from_token`, `user_data`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `TRANSACTION_TYPES`, `STATUS_CHOICES`)
- **URL patterns**: kebab-case (e.g., `/api/register/`, `/api/update-kyc/`)

### File Organization
```
Api/
├── models.py          # All API models
├── views.py            # API views
├── serializers.py      # DRF serializers
├── urls.py            # URL patterns
├── tests/             # Test files
└── management/        # Custom management commands

wallet/
├── models.py          # Wallet models
├── views.py           # Wallet views
├── serializers.py     # Wallet serializers
├── services.py        # Business logic
├── utils.py           # Helper functions
└── test/              # Wallet tests
```

## Environment Configuration

### Required Environment Variables
```bash
SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# Monnify Configuration
MONNIFY_SANDBOX=True
MONNIFY_API_KEY=your-api-key
MONNIFY_SECRET_KEY=your-secret-key
MONNIFY_CONTRACT_CODE=your-contract-code
MONNIFY_MAIN_ACCOUNT_NUMBER=your-account-number
```

### Database
- Default: SQLite3 (`db.sqlite3`)
- PostgreSQL configuration available (commented out in settings)

## Key Dependencies
- Django 5.1.1
- Django REST Framework
- Django Channels (WebSocket support)
- drf-spectacular (API documentation)
- python-decouple (environment variables)
- Pillow (image handling)

## Security Notes
- Token-based authentication
- CORS enabled for all origins (development only)
- Rate limiting applied to sensitive endpoints
- File upload validation (type, size)
- CSRF protection enabled

## API Documentation
- Swagger/OpenAPI available via drf-spectacular
- Access at `/api/docs/` when server is running

## Common Patterns

### Authentication Helper
```python
def get_user_from_token(request):
    try:
        token = request.headers.get('Authorization', '').split(' ')[1]
        token = Token.objects.get(key=token)
        return token.user
    except Exception:
        raise AuthenticationFailed('Invalid token')
```

### File Upload Validation
```python
if isinstance(image_file, InMemoryUploadedFile):
    if not image_file.content_type.startswith('image'):
        return Response({'error': 'Must be an image file'}, status=400)
    if image_file.size > 5 * 1024 * 1024:  # 5MB limit
        return Response({'error': 'File too large'}, status=400)
```

### Response Format
```python
# Success response
return Response({
    'message': 'Operation successful',
    'data': serialized_data
}, status=status.HTTP_200_OK)

# Error response
return Response({
    'error': 'Descriptive error message'
}, status=status.HTTP_400_BAD_REQUEST)
```

## Testing Single Tests

To run a specific test method:
```bash
python manage.py test Api.tests.test_views.RegisterViewTestCase.test_successful_registration
```

To run a specific test class:
```bash
python manage.py test Api.tests.test_views.RegisterViewTestCase
```

Using pytest (if configured):
```bash
pytest -k test_successful_registration
```