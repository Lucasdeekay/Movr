from datetime import timedelta

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.db import IntegrityError, transaction, DatabaseError
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.utils import timezone
# from rest_framework.decorators import permission_classes
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import TokenAuthentication
from .models import Route, ScheduledRoute, Day, Package, Bid, PackageOffer, QRCode, Wallet, Transaction, \
    WithdrawalRequest, PaystackAccount, PaystackTransaction
from .models import CustomUser, KYC, Vehicle, SubscriptionPlan, Subscription, OTP, SocialMediaLink
from .serializers import CustomUserSerializer, OTPVerificationSerializer, TokenSerializer, VehicleSerializer, \
    KYCSerializer, SocialMediaLinkSerializer, RouteSerializer, ScheduledRouteSerializer, PackageSerializer, \
    BidSerializer, PackageOfferSerializer, WalletSerializer, TransactionSerializer, WithdrawalRequestSerializer, \
    PaystackAccountSerializer, PaystackTransactionSerializer, CreatePaystackAccountSerializer, \
    PaystackDepositSerializer, PaystackWithdrawalSerializer, BankSerializer, ResolveAccountSerializer
from rest_framework.authtoken.models import Token
import random


def get_user_from_token(request):
    """
    Extracts the user from the token in the Authorization header.

    :param request: The current request object
    :return: The user associated with the token
    :raises: AuthenticationFailed if token is invalid or missing
    """
    try:
        token = request.headers.get('Authorization', '').split(' ')[1]
        token = Token.objects.get(key=token)
        return token.user
    except Exception:
        raise AuthenticationFailed('Invalid token')

def perform_transfer(sender, receiver_email, amount, message=""):
    """
    Function to perform a transfer between a sender and a receiver.
    """
    try:
        # Validate the receiver
        receiver_wallet = Wallet.objects.get(user__email=receiver_email)
    except Wallet.DoesNotExist:
        raise ValueError("Recipient not found")

    # Fetch sender's wallet
    sender_wallet, _ = Wallet.objects.get_or_create(user=sender)

    # Validate sender's balance
    if sender_wallet.balance < amount:
        raise ValueError("Insufficient funds")

    with transaction.atomic():
        # Deduct amount from sender
        sender_wallet.withdraw(amount)
        sender_wallet.save()

        # Add amount to receiver
        receiver_wallet.deposit(amount)
        receiver_wallet.save()

        # Create transaction records
        Transaction.objects.create(user=sender, transaction_type="transfer", amount=amount, description=f"Transfer to {receiver_email}")
        Transaction.objects.create(user=receiver_wallet.user, transaction_type="deposit", amount=amount, description=f"Received from {sender.email}")

    return {"message": "Transfer successful"}


class RegisterView(APIView):
    """
    API view for user registration.

    This view handles the registration of a new user. It validates the incoming data,
    creates a new user, initializes associated KYC, Vehicle, and Subscription objects,
    and sends an OTP for email verification. Rate limiting is applied to restrict
    the number of registration attempts from the same IP address.

    data : {
            "email": "newuser@example.com",
            "password": "password123",
        }
    """

    @csrf_exempt
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True), name='post')
    def post(self, request, *args, **kwargs):
        """
        Handle POST requests for user registration.

        Args:
            request: The HTTP request object containing the registration data.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: A Response object containing the serialized user data or error messages.
        """

        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            try:
                # Create the user
                user = CustomUser.objects.create(
                    email=serializer.validated_data['email']
                )
                user.set_password(request.data.get('password'))
                user.save()

                # Create default KYC, Vehicle, and free Subscription
                KYC.objects.create(user=user)
                Vehicle.objects.create(user=user)
                free_plan, _ = SubscriptionPlan.objects.get_or_create(name="free")
                Subscription.objects.create(user=user, plan=free_plan)

                # Generate and send OTP for email verification
                otp = OTP.objects.create(user=user)
                otp.send_otp()

                return Response(CustomUserSerializer(user).data, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    """
    API view for verifying One-Time Password (OTP) for email verification.

    This view handles the verification of an OTP sent to a user's email.
    It checks if the provided OTP is valid, not used, and not expired.
    If the OTP is valid, it marks it as used and updates the user's email verification status.
    Rate limiting is applied to restrict the number of verification attempts from the same IP address.

    data : {
            "email": email,
            "code": code,
        }
    """

    @csrf_exempt
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    def post(self, request, *args, **kwargs):
        """
        Handle POST requests for OTP verification.

        Args:
            request: The HTTP request object containing the OTP verification data.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: A Response object indicating the result of the OTP verification.
        """
        try:
            # Retrieve the OTP object based on the user's email and provided code
            otp = OTP.objects.get(
                user__email=request.data['email'],
                code=request.data['code']
            )
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the OTP has already been used
        if otp.is_used:
            return Response({'error': 'OTP has already been used'}, status=status.HTTP_400_BAD_REQUEST)

        print(otp.created_at)
        print(otp.expires_at)
        print(otp.is_expired())
        # Check if the OTP has expired
        if otp.is_expired():
            return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

        # Mark the OTP as used and verify the user's email
        otp.is_used = True
        otp.user.is_email_verified = True
        otp.user.save()
        otp.save()

        return Response({'message': 'Email verified successfully'}, status=status.HTTP_200_OK)


class ResendOTPView(APIView):

    @csrf_exempt
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    def post(self, request, *args, **kwargs):
        """
        Resend a One-Time Password (OTP) to the user's email address.

        This method handles the POST request for resending an OTP. It retrieves the user
        based on the provided email, creates a new OTP for that user, and sends it to
        their email address.

        Parameters:
        request (HttpRequest): The HTTP request object containing the user's data.
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.

        Returns:
        Response: A Django Rest Framework Response object.
            - If successful, returns a 200 OK status with a success message.
            - If the email is invalid, returns a 400 BAD REQUEST status with an error message.

        data : {
            "email": email,
        }
        """
        email = request.data.get('email')
    
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({'error': 'Invalid email or phone number'}, status=status.HTTP_400_BAD_REQUEST)
    
        otp = OTP.objects.create(user=user)
        otp.send_otp()
    
        return Response({'message': 'OTP sent to email'}, status=status.HTTP_200_OK)


class LoginView(APIView):
    """
    API view for user login.

    This view handles user authentication by verifying the provided email and password.
    If the credentials are valid and the user's email is verified, a token is generated
    for the user, and their information is returned in the response. Rate limiting is applied
    to restrict the number of login attempts from the same IP address.

    data : {
            'email': email,
            'password': 'password123'
        }
    """

    @csrf_exempt
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    def post(self, request, *args, **kwargs):
        """
        Handle POST requests for user login.

        Args:
            request: The HTTP request object containing the login data.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: A Response object containing the user's token and information, or an error message.
        """
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({'error': 'Invalid email or phone number'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(email=user.email, password=password)
        if user is not None:
            if not user.is_email_verified:
                return Response({'error': 'Email is not verified'}, status=status.HTTP_400_BAD_REQUEST)
            login(request, user)
            token, _ = Token.objects.get_or_create(user=user)
            return Response({
                'token': TokenSerializer(token).data,
                'user': CustomUserSerializer(user).data,
            }, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    """
    API view for user logout.

    This view handles the logout process for authenticated users.
    It deletes the user's token to ensure they are logged out.
    """

    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handle POST requests for user logout.

        Args:
            request: The HTTP request object containing the user's authentication token.

        Returns:
            Response: A Response object indicating the result of the logout process.
        """
        try:
            # Get the user's token and delete it to log them out
            user = get_user_from_token(request)
            user.auth_token.delete()
            return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        except Token.DoesNotExist:
            return Response({"detail": "Invalid token or user already logged out."}, status=status.HTTP_400_BAD_REQUEST)



class ForgotPasswordRequestOTPView(APIView):
    """
    API view for requesting a password reset OTP.

    This view handles the process of generating a password reset token
    and sending a reset link to the user's registered email address.
    Rate limiting is applied to restrict the number of requests from the same IP address.

    data : {'email': .email}
    """

    @csrf_exempt
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    def post(self, request, *args, **kwargs):
        """
        Handle POST requests for requesting a password reset OTP.

        Args:
            request: The HTTP request object containing the user's email.

        Returns:
            Response: A Response object indicating the result of the password reset request.
        """
        email = request.data.get('email')

        # Check if the user exists
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({'error': 'Email not found'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate a password reset token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Construct the reset link for the mobile app
        reset_link = f"https://yourapp.com/reset-password?uid={uid}&token={token}"

        # Send an email with the reset link
        subject = "Password Reset Request"
        message = (
            f"Hello {user.first_name},\n\n"
            f"Click the link below to reset your password:\n\n"
            f"{reset_link}\n\n"
            "If you did not request a password reset, please ignore this email."
        )
        send_mail(subject, message, 'no-reply@yourapp.com', [user.email])

        return Response({'message': 'Password reset link sent to email'}, status=status.HTTP_200_OK)


class ResetPasswordView(APIView):
    """
    API view for resetting a user's password.

    This view handles the process of resetting a user's password
    using a valid password reset token. It verifies the token and
    user ID, and updates the password if the token is valid.
    Rate limiting is applied to restrict the number of requests
    from the same IP address.

    data : {
            'uid': self.uid,
            'token': self.token,
            'new_password': 'newpassword123',
            'confirm_password': 'newpassword123'
        }
    """

    @csrf_exempt
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    def post(self, request, *args, **kwargs):
        """
        Handle POST requests for resetting a password.

        Args:
            request: The HTTP request object containing the user's ID,
                     token, and new password information.

        Returns:
            Response: A Response object indicating the result of the
                      password reset process.
        """
        uid = request.data.get('uid')
        token = request.data.get('token')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        # Check if the new password and confirm password match
        if new_password != confirm_password:
            return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Decode the user ID
            uid = urlsafe_base64_decode(uid).decode()
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            return Response({'error': 'Invalid user'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the token is valid
        if not default_token_generator.check_token(user, token):
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)

        # Reset the password
        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)



class UpdateKYCView(APIView):
    """
    API view for updating the user's KYC (Know Your Customer) information.

    This view allows authenticated users to update their KYC details.
    If no KYC record exists for the user, a new one is created.
    The view utilizes token-based authentication to ensure that only
    authenticated users can access this endpoint.

    data : {
            "bvn": "98765432101",
            "nin": "98765432101",
            "driver_license": mock_image,
            "verified": False
        }
    """

    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        Handle POST requests for updating KYC information.

        Args:
            request: The HTTP request object containing the KYC data to be updated.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: A Response object indicating the result of the KYC update process.
        """
        user = get_user_from_token(request)  # Retrieve the authenticated user
        data = request.data  # Get the KYC data from the request

        # Check for mandatory fields in the request data
        if 'bvn' not in data or 'nin' not in data:
            return Response(
                {'error': 'Both BVN and NIN are required fields.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate BVN and NIN (assuming they are 11 digits)
        if len(data['bvn']) != 11 or len(data['nin']) != 11:
            return Response(
                {'error': 'Both BVN and NIN must be exactly 11 digits.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get or create a KYC record for the user
        kyc, created = KYC.objects.get_or_create(user=user)

        # If there's an image file, ensure it is a valid image
        if 'driver_license' in data:
            driver_license = data['driver_license']

            if isinstance(driver_license, InMemoryUploadedFile):  # Ensure the file is uploaded correctly
                if not driver_license.content_type.startswith('image'):
                    return Response(
                        {'error': 'Driver license must be an image file.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                if driver_license.size > 5 * 1024 * 1024:  # Limit file size to 5MB
                    return Response(
                        {'error': 'Driver license image size must be under 5MB.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                return Response(
                    {'error': 'Driver license is required to be an image.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Initialize the serializer with the existing KYC data and the new data
        serializer = KYCSerializer(kyc, data=data, partial=True)

        if serializer.is_valid():
            serializer.save()  # Save the updated KYC data
            return Response({'message': 'KYC updated successfully', 'kyc': serializer.data}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UpdateVehicleInfoView(APIView):
    """
    API view for updating the user's vehicle information.

    This view allows authenticated users to update their vehicle details.
    If no vehicle record exists for the user, a new one is created.

    data : {
            "vehicle_plate_number": "XYZ987ABC",
            "vehicle_type": "Truck",
            "vehicle_brand": "Ford",
            "vehicle_color": "Blue",
            "vehicle_photo": mock_image,
            "driver_license": mock_image,
            "vehicle_inspector_report": mock_image,
            "vehicle_insurance": mock_image
        }
    """

    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        Handle POST requests for updating vehicle information.

        Args:
            request: The HTTP request object containing the vehicle data to be updated.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: A Response object indicating the result of the vehicle update process.
        """
        user = get_user_from_token(request)  # Retrieve the authenticated user
        data = request.data  # Get the vehicle data from the request

        # Check for mandatory fields in the request data
        if 'vehicle_plate_number' not in data or 'vehicle_type' not in data:
            return Response(
                {'error': 'Both vehicle_plate_number and vehicle_type are required fields.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate vehicle_plate_number (e.g., should not be empty and be unique)
        if data.get('vehicle_plate_number') and len(data['vehicle_plate_number']) < 4:
            return Response(
                {'error': 'Vehicle plate number must be at least 4 characters long.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get or create a vehicle record for the user
        vehicle, created = Vehicle.objects.get_or_create(user=user)

        # Validate uploaded images if provided
        image_fields = [
            'vehicle_photo',
            'driver_license',
            'vehicle_inspector_report',
            'vehicle_insurance'
        ]

        for field in image_fields:
            if field in data:
                image_file = data[field]

                # Check if the uploaded file is a valid image
                if isinstance(image_file, InMemoryUploadedFile):
                    if not image_file.content_type.startswith('image'):
                        return Response(
                            {'error': f'{field} must be an image file.'},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    # Limit file size to 5MB
                    if image_file.size > 5 * 1024 * 1024:
                        return Response(
                            {'error': f'{field} image size must be under 5MB.'},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'error': f'{field} is required to be a valid image file.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        # Initialize the serializer with the existing vehicle data and the new data
        serializer = VehicleSerializer(vehicle, data=data, partial=True)

        if serializer.is_valid():
            serializer.save()  # Save the updated vehicle data
            return Response(
                {'message': 'Vehicle information updated successfully', 'vehicle': serializer.data},
                status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdatePersonalInfoView(APIView):
    """
    API view for updating a user's personal information and social media links.
    This view handles proper error responses for invalid inputs and constraints.

    data : {
            'first_name': 'John',
            'last_name': 'Doe',
            'phone_number': '0987654321',
            'facebook': 'https://facebook.com/newuser',
            'instagram': 'https://instagram.com/newuser',
            'linkedin': 'https://linkedin.com/in/newuser',
        }
    """

    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]  # To handle file uploads

    def post(self, request, *args, **kwargs):
        """
        Handle POST requests for updating personal information and social media links.
        """
        user = get_user_from_token(request)  # Retrieve the authenticated user
        data = request.data

        # Validate profile picture (if provided)
        profile_picture = data.get('profile_picture')
        if profile_picture:
            if not profile_picture.content_type.startswith('image'):
                return Response(
                    {'error': 'Profile picture must be a valid image file.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if profile_picture.size > 5 * 1024 * 1024:  # Limit size to 5MB
                return Response(
                    {'error': 'Profile picture size must be under 5MB.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Fetch or create social media link instance
        try:
            social_media, _ = SocialMediaLink.objects.get_or_create(user=user)
        except IntegrityError:
            return Response(
                {'error': 'Error fetching or creating social media links.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Initialize serializers
        user_serializer = CustomUserSerializer(user, data=request.data, partial=True)
        social_media_serializer = SocialMediaLinkSerializer(social_media, data=request.data, partial=True)

        # Check for validation errors
        if not user_serializer.is_valid():
            return Response(
                {'user_errors': user_serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not social_media_serializer.is_valid():
            return Response(
                {'social_media_errors': social_media_serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Save updates if serializers are valid
            user_serializer.save()
            social_media_serializer.save()
        except IntegrityError as e:
            # Handle unique field constraint errors (phone, social media links)
            if "unique" in str(e):
                return Response(
                    {'error': 'Provided fields must be unique. Check email, phone number, or social media links.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            return Response(
                {'error': 'An error occurred while updating user information.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except ValidationError as e:
            return Response(
                {'validation_error': e.message_dict},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response({
            'message': 'User information updated successfully',
            'user': user_serializer.data,
            'social_media': social_media_serializer.data
        }, status=status.HTTP_200_OK)



class UpdateSubscriptionPlanView(APIView):
    """
    API view for updating a user's subscription plan.

    This view allows authenticated users to update their subscription plan
    based on the provided plan name. The view utilizes token-based
    authentication to ensure that only authenticated users can access this endpoint.

    data : {'plan_name': 'premium'}
    """

    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        """
        Handle PUT requests for updating the subscription plan.

        Args:
            request: The HTTP request object containing the new subscription plan name.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: A Response object indicating the result of the subscription plan update process.
        """
        user = get_user_from_token(request)  # Retrieve the authenticated user
        plan_name = request.data.get('plan_name')  # Get the plan name from the request data

        if not plan_name:
            return Response({"error": "Plan name is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Retrieve the subscription plan by name
            plan = SubscriptionPlan.objects.get(name=plan_name.lower())
        except SubscriptionPlan.DoesNotExist:
            return Response({"error": "Subscription plan not found."}, status=status.HTTP_404_NOT_FOUND)

        # Get or create a subscription record for the user
        subscription = Subscription.objects.get(user=user)

        # Calculate new end date based on the duration of the plan
        subscription.plan = plan
        subscription.start_date = timezone.now()
        subscription.end_date = subscription.start_date + timedelta(days=plan.duration)
        subscription.save()  # Save the updated subscription information

        return Response({"message": "Subscription plan updated successfully."}, status=status.HTTP_200_OK)


class CreateRouteView(APIView):
    """
    API view for creating a new route.

    This view allows authenticated users to create a new route by providing
    the necessary details such as location, destination, transportation mode,
    and departure time. The view utilizes token-based authentication to ensure
    that only authenticated users can access this endpoint.

    data : {
            "location": "Location A",
            "location_latitude": 40.712776,
            "location_longitude": -74.005974,
            "destination": "Location B",
            "destination_latitude": 34.052235,
            "destination_longitude": -118.243683,
            "transportation_mode": "car",
            "departure_time": timezone.now().isoformat(),
            "service_type": "ride",
        }
    """

    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handle POST requests for creating a new route.

        Args:
            request: The HTTP request object containing the route details.

        Returns:
            Response: A Response object indicating the result of the route creation process.
        """
        # Collect fields from the request
        user = get_user_from_token(request)  # Retrieve the authenticated user
        location = request.data.get('location')
        location_latitude = request.data.get('location_latitude', None)
        location_longitude = request.data.get('location_longitude', None)
        destination = request.data.get('destination')
        destination_latitude = request.data.get('destination_latitude', None)
        destination_longitude = request.data.get('destination_longitude', None)
        stop_location = request.data.get('stop_location', None)
        stop_location_latitude = request.data.get('stop_location_latitude', None)
        stop_location_longitude = request.data.get('stop_location_longitude', None)
        transportation_mode = request.data.get('transportation_mode')
        service_type = request.data.get('service_type', None)
        departure_time = request.data.get('departure_time')
        ticket_image = request.FILES.get('ticket_image', None)
        radius_range = request.FILES.get('radius_range', None)

        # Validate required fields
        if not location or not destination or not transportation_mode or not departure_time:
            return Response({"error": "Location, destination, transportation mode, and departure time are required."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Create and save the Route instance
        route = Route.objects.create(
            user=user,
            location=location,
            location_latitude=location_latitude,
            location_longitude=location_longitude,
            destination=destination,
            destination_latitude=destination_latitude,
            destination_longitude=destination_longitude,
            stop_location=stop_location,
            stop_location_latitude=stop_location_latitude,
            stop_location_longitude=stop_location_longitude,
            transportation_mode=transportation_mode,
            service_type=service_type,
            departure_time=departure_time,
            ticket_image=ticket_image,
            radius_range=radius_range,
        )
        serializer = RouteSerializer(route)  # Serialize the created route instance
        return Response({"message": "Route created successfully.", "route": serializer.data},
                        status=status.HTTP_201_CREATED)


class CreateScheduledRouteView(APIView):
    """
    API view for creating a scheduled route.

    This view allows authenticated users to create a scheduled route by providing
    necessary details such as location, destination, transportation mode, and schedule
    information. The view utilizes token-based authentication to ensure that only
    authenticated users can access this endpoint.

    data : {
            "location": "Location A",
            "location_latitude": 40.712776,
            "location_longitude": -74.005974,
            "destination": "Location B",
            "destination_latitude": 34.052235,
            "destination_longitude": -118.243683,
            "transportation_mode": "car",
            "departure_time": timezone.now().isoformat(),
            "is_returning": "True",
            "returning_time": timezone.now().isoformat(),
            "is_repeated": "True",
            "days_of_week": [self.monday.id, self.tuesday.id],
        }
    """

    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handle POST requests for creating a scheduled route.

        Args:
            request: The HTTP request object containing the route and schedule details.

        Returns:
            Response: A Response object indicating the result of the scheduled route creation process.
                      It includes a success message and the serialized scheduled route data if successful,
                      or an error message if validation fails.
        """
        # Collect fields for the associated Route
        user = get_user_from_token(request)
        location = request.data.get('location')
        location_latitude = request.data.get('location_latitude', None)
        location_longitude = request.data.get('location_longitude', None)
        destination = request.data.get('destination')
        destination_latitude = request.data.get('destination_latitude', None)
        destination_longitude = request.data.get('destination_longitude', None)
        stop_location = request.data.get('stop_location', None)
        stop_location_latitude = request.data.get('stop_location_latitude', None)
        stop_location_longitude = request.data.get('stop_location_longitude', None)
        transportation_mode = request.data.get('transportation_mode')
        service_type = request.data.get('service_type', None)
        departure_time = request.data.get('departure_time')
        ticket_image = request.FILES.get('ticket_image', None)
        radius_range = request.FILES.get('radius_range', None)

        # Validate required fields for the Route
        if not location or not destination or not transportation_mode or not departure_time:
            return Response({"error": "Location, destination, transportation mode, and departure time are required."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Create the Route instance
        route = Route.objects.create(
            user=user,
            location=location,
            location_latitude=location_latitude,
            location_longitude=location_longitude,
            destination=destination,
            destination_latitude=destination_latitude,
            destination_longitude=destination_longitude,
            stop_location=stop_location,
            stop_location_latitude=stop_location_latitude,
            stop_location_longitude=stop_location_longitude,
            transportation_mode=transportation_mode,
            service_type=service_type,
            departure_time=departure_time,
            ticket_image=ticket_image,
            radius_range=radius_range,
        )

        # Collect fields for ScheduledRoute
        is_returning = True if request.data.get('is_returning', False) == 'True' else False
        is_repeated = True if request.data.get('is_repeated', False) == 'True' else False
        returning_time = request.data.get('returning_time', None)
        days_of_week_ids = request.data.get('days_of_week', [])

        # Validate schedule fields
        if is_repeated and not days_of_week_ids:
            return Response({"error": "Days of week must be provided if the route is repeated."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Create the ScheduledRoute instance
        scheduled_route = ScheduledRoute.objects.create(
            route=route,
            is_returning=is_returning,
            returning_time=returning_time,
            is_repeated=is_repeated
        )

        # Add days of the week to the schedule
        for day_id in days_of_week_ids:
            day = get_object_or_404(Day, id=day_id)
            scheduled_route.days_of_week.add(day)

        serializer = ScheduledRouteSerializer(scheduled_route)

        return Response({"message": "Scheduled Route created successfully.", "scheduled_route": serializer.data},
                        status=status.HTTP_201_CREATED)


class UserRoutesView(APIView):
    """
    API view for retrieving a user's routes.

    This view allows authenticated users to retrieve all routes associated with their account.
    It utilizes token-based authentication to ensure that only authenticated users can access this endpoint.
    """

    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Handle GET requests to retrieve the user's routes.

        Args:
            request: The HTTP request object containing the user's authentication token.

        Returns:
            Response: A Response object containing the serialized route data for the authenticated user,
                      with a status code of 200 (OK).
        """
        user = get_user_from_token(request)
        routes = Route.objects.filter(user=user)
        serializer = RouteSerializer(routes, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ToggleIsLiveRouteView(APIView):
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def post(self, request, route_id):
        """
        Toggle the 'is_live' status of a user's route.

        This method allows an authenticated user to toggle the 'is_live' status
        of a specific route identified by its ID. If the route is currently live,
        it will be set to not live, and vice versa.

        Args:
            request: The HTTP request object containing the user's authentication token.
            route_id: The ID of the route to be toggled.

        Returns:
            Response: A Response object containing a message indicating the result
                      of the toggle operation and the new 'is_live' status of the route.
                      If the route is not found, a 404 error response is returned.
        """
        user = get_user_from_token(request)
        try:
            route = Route.objects.get(user=user, id=route_id)
        except Route.DoesNotExist:
            return Response({"error": "Route not found."}, status=status.HTTP_404_NOT_FOUND)

        # Toggle the is_live field
        route.is_live = not route.is_live
        route.save()

        return Response({"message": "Route is_live field updated.", "is_live": route.is_live},
                        status=status.HTTP_200_OK)


class PackageSubmissionView(APIView):
    """
    data : {
            "location": "Origin City",
            "location_latitude": Decimal("40.712776"),
            "location_longitude": Decimal("-74.005974"),
            "destination": "Destination City",
            "destination_latitude": Decimal("34.052235"),
            "destination_longitude": Decimal("-118.243683"),
            "package_type": "Delivery",
            "item_image": item_image,
            "item_description": "Books and gadgets",
            "item_weight": "medium",
            "receiver_name": "John Doe",
            "receiver_phone_number": "1234567890",
            "range_radius": Decimal("10.00"),
        }
    """
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handle POST requests to submit a package.

        Args:
            request: The HTTP request object containing the package details.

        Returns:
            Response: A Response object containing the serialized package data if the submission is successful,
                      with a status code of 201 (Created). If the submission fails, a 400 error response is returned
                      containing the errors.
        """
        user = get_user_from_token(request)
        serializer = PackageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PlaceBidView(APIView):
    """
    data : {
            "price": Decimal("10.00")
        }
    """
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]


    def post(self, request, package_id):
        """
        Handle POST requests to place a bid on a package.

        This method allows an authenticated user to place a bid 
        on a specific package identified by its ID. The user must 
        provide a price for the bid.

        Args:
            request: The HTTP request object containing the user's 
                     authentication token and bid price.
            package_id: The ID of the package on which the bid is 
                        being placed.

        Returns:
            Response: A Response object containing a success message 
                      and the ID of the newly created bid if the bid 
                      is placed successfully, with a status code of 
                      201 (Created). If the price is not provided, 
                      a 400 error response is returned. If the package
                      is not found, a 404 error response is returned.
        """

        mover = get_user_from_token(request)
        price = request.data.get('price')

        if not price:
            return Response({"error": "Price is required to place a bid."}, status=400)

        try:
            package = Package.objects.get(id=package_id)
        except Package.DoesNotExist:
            return Response({"error": "Package not found."}, status=status.HTTP_404_NOT_FOUND)

        # Create a new bid
        bid = Bid.objects.create(
            package=package,
            mover=mover,
            price=price
        )

        return Response({"message": "Bid placed successfully.", "bid_id": bid.id}, status=201)


class GetAllBidsView(APIView):
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def get(self, request, package_id):
        try:
            # Retrieve the package
            package = Package.objects.get(id=package_id)

            # Ensure the user requesting the bids is the owner of the package
            if package.user != request.user:
                return Response({"error": "You are not authorized to view the bids for this package."}, status=403)

            # Retrieve all bids associated with this package
            bids = Bid.objects.filter(package=package)

            # Serialize the bid data
            serializer = BidSerializer(bids, many=True)
            return Response(serializer.data, status=200)

        except Package.DoesNotExist:
            return Response({"error": "Package not found."}, status=404)


class GetBidDetailView(APIView):
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def get(self, request, bid_id):
        try:
            user = get_user_from_token(request)
            # Retrieve the bid using the bid_id
            bid = Bid.objects.get(id=bid_id)

            # Ensure the user requesting the bid details is either the owner of the package or the mover who made the bid
            if bid.package.user != user and bid.mover != user:
                return Response({"error": "You are not authorized to view this bid."}, status=403)

            # Serialize the bid data
            serializer = BidSerializer(bid)
            return Response(serializer.data, status=200)

        except Bid.DoesNotExist:
            return Response({"error": "Bid not found."}, status=404)


class SelectMoverView(APIView):
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def post(self, request, bid_id):
        try:
            user = get_user_from_token(request)

            # Retrieve the bid using the bid_id
            bid = Bid.objects.get(id=bid_id)

            # Ensure the user requesting the bid details is either the owner of the package or the mover who made the bid
            if bid.package.user != user and bid.mover != user:
                return Response({"error": "You are not authorized to select a mover for this package."}, status=403)

            # Check if the bid has already been selected (if that's a business rule you have)
            if PackageOffer.objects.filter(package_bid=bid).exists():
                return Response({"error": "Mover has already been selected for this bid."}, status=400)

            # Create a new QR code for the selected mover
            qr_code = QRCode()
            qr_code.save()

            # Create a PackageOffer for the bid and associate the QR code
            package_offer = PackageOffer.objects.create(package_bid=bid, qr_code=qr_code)

            if bid.package.package_type == 'Schedule':
                package_offer.is_scheduled = True

            package_offer.save()

            return Response({"message": f"{bid.mover.email} has been selected for the delivery."},
                            status=status.HTTP_200_OK)

        except Bid.DoesNotExist:
            return Response({"error": "Bid not found."}, status=status.HTTP_404_NOT_FOUND)


class GetPackageOfferDetailView(APIView):
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def get(self, request, package_offer_id):
        try:
            # Retrieve the package offer using the package_offer_id
            package_offer = PackageOffer.objects.get(id=package_offer_id)

            # Serialize the package offer data
            serializer = PackageOfferSerializer(package_offer)
            return Response(serializer.data, status=200)

        except PackageOffer.DoesNotExist:
            return Response({"error": "Package offer not found."}, status=404)


class PickupConfirmationView(APIView):
    """
    data : {'code': '12345'}
    """
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def post(self, request, package_offer_id):
        package_offer = PackageOffer.objects.get(id=package_offer_id)
        code = request.data.get('code')

        if package_offer.qr_code.code == code:
            # Confirm pickup
            package_offer.is_picked_up = True
            package_offer.save()
            return Response({"message": "Pickup confirmed."}, status=200)
        else:
            return Response({"error": "Invalid code."}, status=400)


class DeliveryConfirmationView(APIView):
    """
    data : {'code': '12345'}
    """
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def post(self, request, package_offer_id):
        package_offer = PackageOffer.objects.get(id=package_offer_id)
        code = request.data.get('code')

        if package_offer.qr_code.code == code:
            # Confirm delivery
            package_offer.is_delivered = True
            package_offer.save()
            return Response({"message": "Delivery confirmed."}, status=200)
        else:
            return Response({"error": "Invalid code."}, status=400)


class DepositView(APIView):
    """
    View to handle wallet deposits.
    """
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            user = get_user_from_token(request)
            amount = request.data.get("amount")

            # Validate amount
            if not amount:
                return Response({"error": "Amount is required."}, status=status.HTTP_400_BAD_REQUEST)

            try:
                amount = float(amount)
            except ValueError:
                return Response({"error": "Amount must be a valid number."}, status=status.HTTP_400_BAD_REQUEST)

            if amount <= 0:
                return Response({"error": "Amount must be greater than zero."}, status=status.HTTP_400_BAD_REQUEST)

            # Get or create wallet
            wallet, _ = Wallet.objects.get_or_create(user=user)

            # Update wallet balance
            wallet.deposit(amount)
            wallet.save()

            # Create transaction record
            Transaction.objects.create(user=user, transaction_type="deposit", amount=amount, description="Wallet deposit")

            # Serialize and return updated wallet
            serializer = WalletSerializer(wallet)
            return Response({"message": "Deposit successful", "wallet": serializer.data}, status=status.HTTP_200_OK)

        except IntegrityError:
            return Response({"error": "Database integrity error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except DatabaseError:
            return Response({"error": "A database error occurred. Please try again later."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class WithdrawView(APIView):
    """
    View to handle wallet withdrawal requests.
    """
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            user = request.user  # Assuming `request.user` is provided by the authentication class.

            # Extract and validate request data
            amount = request.data.get("amount")
            bank_name = request.data.get("bank_name")
            account_number = request.data.get("account_number")

            if not amount:
                return Response({"error": "Amount is required."}, status=status.HTTP_400_BAD_REQUEST)

            try:
                amount = float(amount)
            except ValueError:
                return Response({"error": "Amount must be a valid number."}, status=status.HTTP_400_BAD_REQUEST)

            if amount <= 0:
                return Response({"error": "Amount must be greater than zero."}, status=status.HTTP_400_BAD_REQUEST)

            if not bank_name or not account_number:
                return Response(
                    {"error": "Bank name and account number are required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Get user's wallet
            wallet = Wallet.objects.filter(user=user).first()
            if not wallet:
                return Response({"error": "Wallet not found for the user."}, status=status.HTTP_404_NOT_FOUND)

            if wallet.balance < amount:
                return Response(
                    {"error": f"Insufficient funds. Your current balance is {wallet.balance:.2f}."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Create withdrawal request and update wallet balance atomically
            with transaction.atomic():
                # Deduct amount from wallet balance
                wallet.balance -= amount
                wallet.save()

                # Create a withdrawal request
                withdrawal_request = WithdrawalRequest.objects.create(
                    user=user,
                    amount=amount,
                    bank_name=bank_name,
                    account_number=account_number,
                )

            # Serialize and return the withdrawal request details
            withdrawal_serializer = WithdrawalRequestSerializer(withdrawal_request)
            wallet_serializer = WalletSerializer(wallet)

            return Response(
                {
                    "message": "Withdrawal request submitted successfully.",
                    "withdrawal_request": withdrawal_serializer.data,
                    "wallet": wallet_serializer.data,
                },
                status=status.HTTP_201_CREATED,
            )

        except IntegrityError:
            return Response(
                {"error": "A database integrity error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        except DatabaseError:
            return Response(
                {"error": "A database error occurred. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        except Exception as e:
            return Response(
                {"error": f"An unexpected error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class WalletDetailsView(APIView):
    """
    View to return wallet details and transactions of the authenticated user.
    """
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            user = get_user_from_token(request)

            # Fetch wallet
            wallet = Wallet.objects.filter(user=user).first()
            if not wallet:
                return Response({"error": "Wallet not found for the user."}, status=status.HTTP_404_NOT_FOUND)

            # Serialize wallet details
            wallet_serializer = WalletSerializer(wallet)

            # Fetch and serialize transactions
            transactions = Transaction.objects.filter(user=user).order_by('-created_at')
            transaction_serializer = TransactionSerializer(transactions, many=True)

            return Response({
                "wallet": wallet_serializer.data,
                "transactions": transaction_serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PickedUpPackageOffersView(APIView):
    """
    View to retrieve all package offers that have been picked up for the authenticated user.
    """
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = get_user_from_token(request)
            package_offers = PackageOffer.objects.filter(
                package_bid__package__user=user,
                is_picked_up=True,
                is_cancelled=False
            )
            serializer = PackageOfferSerializer(package_offers, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ScheduledPackageOffersView(APIView):
    """
    View to retrieve all scheduled package offers for the authenticated user.
    """
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = get_user_from_token(request)
            package_offers = PackageOffer.objects.filter(
                package_bid__package__user=user,
                is_scheduled=True,
                is_cancelled=False
            )
            serializer = PackageOfferSerializer(package_offers, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CancelPackageOfferView(APIView):
    """
    View to cancel a package offer for the authenticated user.
    """
    authentication_classes = [TokenAuthentication]
#     permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            user = get_user_from_token(request)
            package_offer = PackageOffer.objects.get(
                id=pk,
                package_bid__package__user=user
            )
            package_offer.is_cancelled = True
            package_offer.save()
            return Response({"message": "Package offer cancelled successfully."}, status=status.HTTP_200_OK)
        except PackageOffer.DoesNotExist:
            return Response({"error": "Package offer not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Paystack Views
class PaystackAccountView(APIView):
    """
    View to handle Paystack DVA account operations
    """
    authentication_classes = [TokenAuthentication]
    
    def get(self, request):
        """Get user's Paystack account details"""
        try:
            user = get_user_from_token(request)
            try:
                account = PaystackAccount.objects.get(user=user)
                serializer = PaystackAccountSerializer(account)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except PaystackAccount.DoesNotExist:
                return Response({"message": "No Paystack account found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request):
        """Create a new Paystack DVA account"""
        try:
            user = get_user_from_token(request)
            serializer = CreatePaystackAccountSerializer(data=request.data)
            
            if serializer.is_valid():
                # Check if user already has an account
                if PaystackAccount.objects.filter(user=user).exists():
                    return Response({"error": "User already has a Paystack account"}, status=status.HTTP_400_BAD_REQUEST)
                
                # Create DVA account using Paystack service
                from .paystack_service import paystack_service
                success, response = paystack_service.create_dva_account(
                    user=user,
                    preferred_bank=serializer.validated_data.get('preferred_bank')
                )
                
                if success:
                    account = PaystackAccount.objects.get(user=user)
                    account_serializer = PaystackAccountSerializer(account)
                    return Response({
                        "message": "Paystack account created successfully",
                        "account": account_serializer.data
                    }, status=status.HTTP_201_CREATED)
                else:
                    return Response({"error": response.get('error', 'Failed to create account')}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PaystackDepositView(APIView):
    """
    View to handle Paystack deposits
    """
    authentication_classes = [TokenAuthentication]
    
    def post(self, request):
        """Initiate a Paystack deposit"""
        try:
            user = get_user_from_token(request)
            serializer = PaystackDepositSerializer(data=request.data)
            
            if serializer.is_valid():
                amount = serializer.validated_data['amount']
                email = serializer.validated_data['email']
                reference = serializer.validated_data.get('reference')
                callback_url = serializer.validated_data.get('callback_url')
                
                # Create transaction record
                transaction = PaystackTransaction.objects.create(
                    user=user,
                    transaction_type='deposit',
                    paystack_reference=reference or f"DEP_{user.id}_{int(timezone.now().timestamp())}",
                    amount=amount,
                    status='pending'
                )
                
                # Initialize Paystack transaction
                from .paystack_service import paystack_service
                import uuid
                
                # Generate unique reference if not provided
                if not reference:
                    reference = f"DEP_{user.id}_{uuid.uuid4().hex[:8]}"
                    transaction.paystack_reference = reference
                    transaction.save()
                
                # Create Paystack transaction data
                transaction_data = {
                    'email': email,
                    'amount': int(amount * 100),  # Convert to kobo
                    'reference': reference,
                    'callback_url': callback_url or f"{request.build_absolute_uri('/')}api/paystack/webhook/",
                    'currency': 'NGN'
                }
                
                # Make request to Paystack
                success, response = paystack_service._make_request('POST', '/transaction/initialize', transaction_data)
                
                if success:
                    return Response({
                        "message": "Deposit initiated successfully",
                        "authorization_url": response.get('data', {}).get('authorization_url'),
                        "reference": reference,
                        "transaction_id": transaction.id
                    }, status=status.HTTP_200_OK)
                else:
                    transaction.status = 'failed'
                    transaction.gateway_response = response.get('error', 'Failed to initialize transaction')
                    transaction.save()
                    return Response({"error": response.get('error', 'Failed to initialize deposit')}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PaystackWithdrawalView(APIView):
    """
    View to handle Paystack withdrawals
    """
    authentication_classes = [TokenAuthentication]
    
    def post(self, request):
        """Initiate a Paystack withdrawal"""
        try:
            user = get_user_from_token(request)
            serializer = PaystackWithdrawalSerializer(data=request.data)
            
            if serializer.is_valid():
                amount = serializer.validated_data['amount']
                bank_code = serializer.validated_data['bank_code']
                account_number = serializer.validated_data['account_number']
                account_name = serializer.validated_data['account_name']
                narration = serializer.validated_data.get('narration', 'Withdrawal')
                
                # Check if user has sufficient balance
                wallet, created = Wallet.objects.get_or_create(user=user)
                if wallet.balance < amount:
                    return Response({"error": "Insufficient funds"}, status=status.HTTP_400_BAD_REQUEST)
                
                # Create recipient first
                from .paystack_service import paystack_service
                success, recipient_response = paystack_service.create_recipient(
                    account_number=account_number,
                    bank_code=bank_code,
                    name=account_name
                )
                
                if not success:
                    return Response({"error": "Failed to create recipient"}, status=status.HTTP_400_BAD_REQUEST)
                
                recipient_code = recipient_response.get('data', {}).get('recipient_code')
                
                # Create transaction record
                import uuid
                reference = f"WTH_{user.id}_{uuid.uuid4().hex[:8]}"
                transaction = PaystackTransaction.objects.create(
                    user=user,
                    transaction_type='withdrawal',
                    paystack_reference=reference,
                    amount=amount,
                    status='pending',
                    narration=narration
                )
                
                # Initiate transfer
                success, transfer_response = paystack_service.initiate_transfer(
                    recipient_code=recipient_code,
                    amount=amount,
                    reason=narration
                )
                
                if success:
                    transfer_data = transfer_response.get('data', {})
                    transaction.paystack_transaction_id = transfer_data.get('id')
                    transaction.save()
                    
                    # Deduct from wallet
                    wallet.withdraw(amount)
                    
                    return Response({
                        "message": "Withdrawal initiated successfully",
                        "reference": reference,
                        "transaction_id": transaction.id
                    }, status=status.HTTP_200_OK)
                else:
                    transaction.status = 'failed'
                    transaction.gateway_response = transfer_response.get('error', 'Failed to initiate transfer')
                    transaction.save()
                    return Response({"error": transfer_response.get('error', 'Failed to initiate withdrawal')}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PaystackWebhookView(APIView):
    """
    View to handle Paystack webhooks
    """
    authentication_classes = []
    permission_classes = []
    
    def post(self, request):
        """Handle Paystack webhook"""
        try:
            # Get the signature from headers
            signature = request.headers.get('X-Paystack-Signature')
            if not signature:
                return Response({"error": "No signature provided"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Process webhook
            from .paystack_service import paystack_service
            success = paystack_service.process_webhook(request.data, signature)
            
            if success:
                return Response({"status": "success"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Webhook processing failed"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PaystackBanksView(APIView):
    """
    View to get list of available banks
    """
    authentication_classes = [TokenAuthentication]
    
    def get(self, request):
        """Get list of available banks"""
        try:
            from .paystack_service import paystack_service
            success, response = paystack_service.get_banks()
            
            if success:
                banks = response.get('data', [])
                return Response({"banks": banks}, status=status.HTTP_200_OK)
            else:
                return Response({"error": response.get('error', 'Failed to fetch banks')}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PaystackResolveAccountView(APIView):
    """
    View to resolve account number
    """
    authentication_classes = [TokenAuthentication]
    
    def post(self, request):
        """Resolve account number to get account details"""
        try:
            serializer = ResolveAccountSerializer(data=request.data)
            
            if serializer.is_valid():
                account_number = serializer.validated_data['account_number']
                bank_code = serializer.validated_data['bank_code']
                
                from .paystack_service import paystack_service
                success, response = paystack_service.resolve_account_number(account_number, bank_code)
                
                if success:
                    account_data = response.get('data', {})
                    return Response({
                        "account_name": account_data.get('account_name'),
                        "account_number": account_data.get('account_number'),
                        "bank_id": account_data.get('bank_id')
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({"error": response.get('error', 'Failed to resolve account')}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PaystackTransactionsView(APIView):
    """
    View to get user's Paystack transactions
    """
    authentication_classes = [TokenAuthentication]
    
    def get(self, request):
        """Get user's Paystack transactions"""
        try:
            user = get_user_from_token(request)
            transactions = PaystackTransaction.objects.filter(user=user).order_by('-created_at')
            serializer = PaystackTransactionSerializer(transactions, many=True)
            return Response({"transactions": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
