# Movr - Transportation & Logistics Platform

A Django-based transportation and logistics platform with real-time features, payments, and more.

## Features

- **Authentication**: OTP-based email verification, token auth
- **KYC**: BVN, NIN, driver license verification
- **Vehicles**: Registration and management
- **Routes**: Creation, scheduling, live tracking
- **Packages**: Delivery system with bidding
- **Wallet**: Monnify integration for payments
- **Real-time**: WebSocket notifications via Django Channels
- **Chat**: Real-time messaging between drivers and users
- **Presence**: Online/offline status tracking
- **Location**: Live location tracking
- **Emergency SOS**: Emergency alert system

## Tech Stack

- Django 5.1.1
- Django REST Framework
- Django Channels (WebSocket)
- PostgreSQL
- Redis (for channel layers)
- Monnify (payments)

## Getting Started

### Prerequisites

- Python 3.10+
- PostgreSQL
- Redis

### Installation

1. Clone the repository
2. Create virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables in `.env`:
   ```env
   SECRET_KEY=your-secret-key
   DEBUG=True
   ALLOWED_HOSTS=localhost,127.0.0.1
   EMAIL_HOST_USER=your-email
   EMAIL_HOST_PASSWORD=your-email-password

   # Monnify
   MONNIFY_SANDBOX=True
   MONNIFY_API_KEY=your-api-key
   MONNIFY_SECRET_KEY=your-secret
   MONNIFY_CONTRACT_CODE=your-contract-code
   MONNIFY_MAIN_ACCOUNT_NUMBER=your-account-number

   # Database
   POSTGRES_NAME=movr
   POSTGRES_USER=postgres
   POSTGRES_PASSWORD=password
   POSTGRES_HOST=localhost
   POSTGRES_PORT=5432
   ```

5. Run migrations:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. Create superuser:
   ```bash
   python manage.py createsuperuser
   ```

7. Seed data (optional):
   ```bash
   python manage.py seed_data
   ```

8. Run development server:
   ```bash
   python manage.py runserver
   ```

## API Endpoints

### Authentication
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/register/` | POST | User registration |
| `/api/verify-otp/` | POST | Verify email via OTP |
| `/api/resend-otp/` | POST | Resend OTP |
| `/api/login/` | POST | User login |
| `/api/logout/` | POST | User logout |

### User Profile
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/update-kyc/` | POST | Update KYC info |
| `/api/update-vehicle/` | POST | Update vehicle info |
| `/api/update-personal-info/` | POST | Update name/phone |
| `/api/upload-profile-image/` | POST | Upload profile picture |

### Routes
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/routes/create-route/` | POST | Create new route |
| `/routes/create-scheduled-route/` | POST | Create scheduled route |
| `/routes/user-routes/` | GET | List user's routes |
| `/routes/toggle-is-live/<uuid:route_id>/` | POST | Toggle route live status |
| `/routes/scheduled-routes/` | GET | Get scheduled routes |
| `/routes/live-routes-count/` | GET | Get live routes count |
| `/routes/days/` | GET | Get days list |

### Packages
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/packages/submit-package/` | POST | Submit package for delivery |
| `/packages/place-bid/<uuid:package_id>/` | POST | Place bid on package |
| `/packages/package/<uuid:package_id>/bids/` | GET | Get all bids for package |
| `/packages/select-mover/<uuid:bid_id>/` | POST | Accept bid |
| `/packages/package-offers/` | GET | Get all package offers |
| `/packages/confirm-pickup/<uuid:package_offer_id>/` | POST | Mark as picked up |
| `/packages/confirm-delivery/<uuid:package_offer_id>/` | POST | Mark as delivered |

### Chat
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/chat/send/` | POST | Send chat message |
| `/chat/<uuid:conversation_id>/` | GET | Get conversation messages |
| `/chat/conversations/` | GET | List user conversations |
| `/chat/create/` | POST | Create new conversation |

### Presence
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/presence/update/` | POST | Update presence status |
| `/presence/online/` | GET | Get online users |
| `/presence/user/<uuid:user_id>/` | GET | Get user location |

### Emergency SOS
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/emergency/trigger/` | POST | Trigger emergency SOS |
| `/emergency/alerts/` | GET | Get SOS alerts |
| `/emergency/acknowledge/<uuid:sos_id>/` | POST | Admin acknowledge SOS |
| `/emergency/resolve/<uuid:sos_id>/` | POST | Admin resolve SOS |

### Wallet
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/wallet/api/wallets/` | GET/POST | Wallet CRUD |
| `/wallet/api/wallets/my-wallet/` | GET | Get user's wallet |
| `/wallet/api/transactions/` | GET | List transactions |
| `/wallet/api/withdrawals/` | GET/POST | Withdrawal CRUD |
| `/wallet/api/resolve-account-number/` | POST | Validate bank account |
| `/wallet/api/banks/` | GET | List banks |
| `/wallet/api/webhook/monnify/` | POST | Monnify webhook |

## WebSocket Endpoints

| Endpoint | Description |
|----------|-------------|
| `ws/live-routes/?token=<token>` | Live routes count |
| `ws/notifications/?token=<token>` | Notifications, trip updates |
| `ws/chat/?token=<token>` | Real-time chat messages |
| `ws/presence/?token=<token>` | Presence and location updates |

## Testing

```bash
# All tests
python manage.py test

# App-specific tests
python manage.py test Chat.tests
python manage.py test Presence.tests
python manage.py test Emergency.tests
python manage.py test Routes.tests
python manage.py test Packages.tests
python manage.py test wallet.tests
```

## License

MIT
