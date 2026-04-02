# AGENTS.md - Movr System Documentation

**IMPORTANT: Always read this file when starting work on this repository. Update it whenever changes are made to the system.**

---

## Project Overview

Movr is a Django-based transportation and logistics platform with the following features:
- **Authentication**: OTP-based email verification, token auth
- **KYC**: BVN, NIN, driver license verification
- **Vehicles**: Registration and management
- **Routes**: Creation, scheduling, live tracking
- **Packages**: Delivery system with bidding
- **Wallet**: Paystack/Monnify integration for payments
- **Real-time**: WebSocket notifications via Django Channels
- **Chat**: Real-time messaging between drivers and users
- **Presence**: Online/offline status tracking
- **Location**: Live location tracking (10s frequency)
- **Emergency SOS**: Emergency alert system

---

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
# All tests
python manage.py test
pytest -q

# Auth app tests
python manage.py test Auth.tests
pytest Auth/tests/ -v

# Profile app tests
python manage.py test Profile.tests
pytest Profile/tests/ -v

# Chat app tests
python manage.py test Chat.tests
pytest Chat/tests/ -v

# Presence app tests
python manage.py test Presence.tests
pytest Presence/tests/ -v

# Emergency app tests
python manage.py test Emergency.tests
pytest Emergency/tests/ -v

# Routes app tests
python manage.py test Routes.tests
pytest Routes/tests/ -v

# Packages app tests
python manage.py test Packages.tests
pytest Packages/tests/ -v

# Wallet app tests
python manage.py test wallet.tests
pytest wallet/tests/ -v
```

### Code Quality
```bash
flake8 .  # If installed
black .   # If installed
```

---

## Code Style Guidelines

### Import Order
```python
# Standard library
import os
from datetime import datetime

# Third-party
from django.db import models
from rest_framework import status

# Local
from Auth.models import CustomUser
from Profile.models import KYC, Vehicle
from wallet.services import create_dedicated_account
```

### Model Conventions
- Use `UUIDModel` as base class (provides UUID pk + created_at/updated_at)
- Include `verbose_name`, `verbose_name_plural`, `ordering`, `help_text`
- Define `__str__` for all models

### View Conventions
- Use `TokenAuthentication` for protected endpoints
- Use `get_user_from_token(request)` helper for auth
- Return consistent `Response({'message': ..., 'data': ...})` format

### Naming
- Models: `PascalCase` (e.g., `CustomUser`)
- Views: `PascalCase` + `View` suffix
- Serializers: `PascalCase` + `Serializer` suffix
- URLs: `kebab-case` with versioning (e.g., `/auth/v1/register/`)

---

## System Architecture

### Core Apps

#### 1. Auth App (`Auth/`)
**Models:**
- `CustomUser` - Extended user with email, phone, profile_picture
- `OTP` - One-time password for verification
- `UUIDModel` - Base abstract model with UUID pk + timestamps

**Views:**
- `get_user_from_token(request)` - Helper to extract user from auth token

**URLs:** `/auth/v1/`

#### 2. Profile App (`Profile/`)
**Models:**
- `KYC` - Know Your Customer (bvn, nin, driver_license, verified)
- `Vehicle` - Vehicle details (plate, type, brand, color, photos)
- `SubscriptionPlan` - Plans: free, basic, rover, courier, courier_plus
- `Subscription` - User subscription tracking
- `SocialMediaLink` - User social media links
- `Notification` - User notifications
- `Badge`, `UserBadge` - Gamification
- `ReferralToken`, `Referral` - Referral system
- `UUIDModel` - Base abstract model with UUID pk + timestamps

**URLs:** `/profile/v1/`

#### 3. Wallet App (`wallet/`)
**Models:**
- `Wallet` - User wallet with balance, DVA (Dedicated Virtual Account)
- `Transaction` - Deposit, withdrawal, transfer records
- `Withdrawal` - Withdrawal requests with bank details
- `Bank` - Supported banks with codes

**Services:**
- `create_dedicated_account_for_user(user)` - Creates Monnify DVA
- `fetch_reserved_account_details(user)` - Gets DVA details
- `fetch_balance_from_monnify(wallet)` - Gets balance from Monnify
- `initiate_withdrawal(user, amount, bank_name, account_number)` - Processes withdrawal

#### 4. Routes App (`Routes/`)
- `Route`, `ScheduledRoute`, `Day` - Route management
- `UUIDModel` - Base abstract model with UUID pk + timestamps

#### 5. Packages App (`Packages/`)
- `Package`, `Bid`, `PackageOffer`, `QRCode` - Package delivery system
- `UUIDModel` - Base abstract model with UUID pk + timestamps

#### 6. Chat App (`Chat/`)
- `ChatConversation`, `ChatMessage` - Real-time chat
- `UUIDModel` - Base abstract model with UUID pk + timestamps

#### 7. Presence App (`Presence/`)
- `UserPresence` - Online/offline status and location
- `UUIDModel` - Base abstract model with UUID pk + timestamps

#### 8. Emergency App (`Emergency/`)
- `EmergencySOS` - Emergency SOS alerts
- `UUIDModel` - Base abstract model with UUID pk + timestamps

---

## API Endpoints (Versioned)

### Authentication (`/auth/v1/`)
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/auth/v1/register/` | POST | No | User registration |
| `/auth/v1/verify-otp/` | POST | No | Verify email via OTP |
| `/auth/v1/resend-otp/` | POST | No | Resend OTP |
| `/auth/v1/login/` | POST | No | User login |
| `/auth/v1/logout/` | POST | Yes | User logout |
| `/auth/v1/forgot-password/` | POST | No | Request password reset |
| `/auth/v1/reset-password/` | POST | No | Reset password |
| `/auth/v1/api/users/` | GET/POST | Yes | User ViewSet |

### User Profile (`/profile/v1/`)
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/profile/v1/update-kyc/` | POST | Yes | Update KYC info |
| `/profile/v1/update-vehicle/` | POST | Yes | Update vehicle info |
| `/profile/v1/update-personal-info/` | POST | Yes | Update name/phone |
| `/profile/v1/upload-profile-image/` | POST | Yes | Upload profile picture |
| `/profile/v1/update-subscription/` | POST | Yes | Change subscription plan |
| `/profile/v1/notifications/` | GET | Yes | Get notifications |
| `/profile/v1/notifications/<uuid>/mark-read/` | POST | Yes | Mark notification read |
| `/profile/v1/social-media/` | POST | Yes | Update social media links |
| `/profile/v1/api/kyc/` | GET/POST | Yes | KYC ViewSet |
| `/profile/v1/api/vehicles/` | GET/POST | Yes | Vehicle ViewSet |
| `/profile/v1/api/subscription-plans/` | GET/POST | Yes | SubscriptionPlan ViewSet |
| `/profile/v1/api/notifications/` | GET/POST | Yes | Notification ViewSet |

### Routes (`/routes/`)
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/routes/create-route/` | POST | Yes | Create new route |
| `/routes/create-scheduled-route/` | POST | Yes | Create scheduled route |
| `/routes/user-routes/` | GET | Yes | List user's routes |
| `/routes/toggle-is-live/<uuid:route_id>/` | POST | Yes | Toggle route live status |
| `/routes/scheduled-routes/` | GET | Yes | Get scheduled routes |
| `/routes/live-routes-count/` | GET | Yes | Get live routes count |
| `/routes/days/` | GET | Yes | Get days list |

### Packages (`/packages/`)
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/packages/submit-package/` | POST | Yes | Submit package for delivery |
| `/packages/place-bid/<uuid:package_id>/` | POST | Yes | Place bid on package |
| `/packages/package/<uuid:package_id>/bids/` | GET | Yes | Get all bids for package |
| `/packages/bid/<uuid:bid_id>/` | GET | Yes | Get bid detail |
| `/packages/select-mover/<uuid:bid_id>/` | POST | Yes | Accept bid |
| `/packages/package-offers/` | GET | Yes | Get all package offers |
| `/packages/package-offer/<uuid:package_offer_id>/` | GET | Yes | Get package offer detail |
| `/packages/confirm-pickup/<uuid:package_offer_id>/` | POST | Yes | Mark as picked up |
| `/packages/confirm-delivery/<uuid:package_offer_id>/` | POST | Yes | Mark as delivered |
| `/packages/offers/picked-up/` | GET | Yes | Get picked up offers |
| `/packages/offers/scheduled/` | GET | Yes | Get scheduled offers |
| `/packages/offers/<uuid:pk>/cancel/` | POST | Yes | Cancel package offer |

### Chat (`/chat/`)
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/chat/send/` | POST | Yes | Send chat message |
| `/chat/<uuid:conversation_id>/` | GET | Yes | Get conversation messages |
| `/chat/conversations/` | GET | Yes | List user conversations |
| `/chat/create/` | POST | Yes | Create new conversation |

### Presence (`/presence/`)
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/presence/update/` | POST | Yes | Update presence status |
| `/presence/online/` | GET | Yes | Get online users |
| `/presence/user/<uuid:user_id>/` | GET | Yes | Get user location |

### Emergency SOS (`/emergency/`)
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/emergency/trigger/` | POST | Yes | Trigger emergency SOS |
| `/emergency/alerts/` | GET | Yes | Get SOS alerts |
| `/emergency/acknowledge/<uuid:sos_id>/` | POST | Yes | Admin acknowledge SOS |
| `/emergency/resolve/<uuid:sos_id>/` | POST | Yes | Admin resolve SOS |

### Wallet (`/wallet/api/`)
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/wallet/api/wallets/` | GET/POST | Yes | Wallet CRUD |
| `/wallet/api/wallets/my-wallet/` | GET | Yes | Get user's wallet |
| `/wallet/api/transactions/` | GET | Yes | List transactions |
| `/wallet/api/transactions/<uuid:transaction_id>/` | GET | Yes | Transaction detail |
| `/wallet/api/withdrawals/` | GET/POST | Yes | Withdrawal CRUD |
| `/wallet/api/resolve-account-number/` | POST | Yes | Validate bank account |
| `/wallet/api/banks/` | GET | Yes | List banks |
| `/wallet/api/webhook/monnify/` | POST | No | Monnify webhook |

---

## WebSocket Endpoints

### Real-Time Features

| Endpoint | Consumer | Description |
|----------|----------|-------------|
| `ws/live-routes/?token=<token>` | TotalLiveRoutesConsumer | Live routes count |
| `ws/notifications/?token=<token>` | NotificationConsumer | Notifications, trip updates, payments |
| `ws/chat/?token=<token>` | ChatConsumer | Real-time chat messages |
| `ws/presence/?token=<token>` | PresenceConsumer | Presence and location updates |

### WebSocket Message Types

**Outgoing (Server → Client):**
```json
{"type": "live_routes_count", "count": 5}
{"type": "notification", "title": "...", "message": "..."}
{"type": "trip_update", "trip_id": "...", "status": "..."}
{"type": "payment", "reference": "...", "status": "completed"}
{"type": "chat_message", "message": {"id": "...", "sender": "...", "message": "..."}}
{"type": "presence", "user_id": "...", "is_online": true}
{"type": "location", "user_id": "...", "latitude": ..., "longitude": ...}
{"type": "ride_request", "package_id": "...", "location": "...", "destination": "..."}
{"type": "sos_alert", "alert": {...}}
```

**Incoming (Client → Server):**
```json
{"type": "chat_message", "conversation_id": "...", "message": "..."}
{"type": "typing", "conversation_id": "...", "is_typing": true}
{"type": "read_receipt", "message_id": "..."}
{"type": "location_update", "latitude": ..., "longitude": ...}
```

---

## Environment Variables

```bash
SECRET_KEY=
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
EMAIL_HOST_USER=
EMAIL_HOST_PASSWORD=

# Monnify
MONNIFY_SANDBOX=True
MONNIFY_API_KEY=
MONNIFY_SECRET_KEY=
MONNIFY_CONTRACT_CODE=
MONNIFY_MAIN_ACCOUNT_NUMBER=

# PostgreSQL (Production)
POSTGRES_NAME=
POSTGRES_USER=
POSTGRES_PASSWORD=
POSTGRES_HOST=
POSTGRES_PORT=
```

---

## Key Dependencies

- Django 5.1.1
- Django REST Framework
- Django Channels (WebSocket)
- channels-redis (Redis for channel layers)
- drf-spectacular (API docs)
- python-decouple (env vars)
- Pillow (images)
- django-ratelimit
- psycopg2 (PostgreSQL)

---

## Common Patterns

### Authentication Helper
```python
from Auth.views import get_user_from_token

def get_user_from_token(request):
    try:
        token = request.headers.get('Authorization', '').split(' ')[1]
        return Token.objects.get(key=token).user
    except Exception:
        raise AuthenticationFailed('Invalid token')
```

### Response Format
```python
# Success
return Response({'message': 'Success', 'data': serializer.data}, status=200)

# Error
return Response({'error': 'Error message'}, status=400)
```

### WebSocket Broadcast Example
```python
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

channel_layer = get_channel_layer()
async_to_sync(channel_layer.group_send)(
    f"user_{user_id}",
    {
        "type": "notification",
        "title": "New Message",
        "message": "You have a new message",
    }
)
```

---

## Maintenance Notes

- Update this file when adding new models, views, or endpoints
- Document new services in the Services section
- Add new environment variables to the Environment Variables section
- Keep test commands updated for new test files
- Include new API endpoints in the API Endpoints table
- Update WebSocket documentation for new real-time features
- Run migrations after adding new apps: `python manage.py makemigrations && python manage.py migrate`

**Last Updated: 2026-04-02**