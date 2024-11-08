from datetime import timedelta

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from .models import Route, ScheduledRoute, Day, Package, Bid, PackageOffer, QRCode
from .models import CustomUser, KYC, Vehicle, SubscriptionPlan, Subscription, OTP, SocialMediaLink
from .serializers import CustomUserSerializer, OTPVerificationSerializer, TokenSerializer, VehicleSerializer, \
    KYCSerializer, SocialMediaLinkSerializer, RouteSerializer, ScheduledRouteSerializer, PackageSerializer, \
    BidSerializer, PackageOfferSerializer
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


class RegisterView(APIView):
    """
    API view for user registration.

    This view handles the registration of a new user. It validates the incoming data,
    creates a new user, initializes associated KYC, Vehicle, and Subscription objects,
    and sends an OTP for email verification. Rate limiting is applied to restrict
    the number of registration attempts from the same IP address.
    """

    @csrf_exempt
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
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
                    email=serializer.validated_data['email'],
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
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                # Retrieve the OTP object based on the user's email and provided code
                otp = OTP.objects.get(
                    user__email=serializer.validated_data['email'],
                    code=serializer.validated_data['code']
                )
            except OTP.DoesNotExist:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

            # Check if the OTP has already been used
            if otp.is_used:
                return Response({'error': 'OTP has already been used'}, status=status.HTTP_400_BAD_REQUEST)

            # Check if the OTP has expired
            if otp.is_expired():
                return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

            # Mark the OTP as used and verify the user's email
            otp.is_used = True
            otp.user.is_email_verified = True
            otp.user.save()
            otp.save()

            return Response({'message': 'Email verified successfully'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
    It retrieves the user's token, logs them out, and deletes the token
    to ensure the user is logged out successfully.
    """

    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handle POST requests for user logout.

        Args:
            request: The HTTP request object containing the user's authentication token.

        Returns:
            Response: A Response object indicating the result of the logout process.
        """
        # Retrieve the token for the authenticated user
        try:
            user = get_user_from_token(request)  # Function to retrieve user from token
            logout(user)  # Log out the user
            token = Token.objects.get(user=user)  # Get the user's token
            # Delete the token to log out the user
            token.delete()
            return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        except Token.DoesNotExist:
            return Response({"detail": "Invalid token or user already logged out."}, status=status.HTTP_400_BAD_REQUEST)


class ForgotPasswordRequestOTPView(APIView):
    """
    API view for requesting a password reset OTP.

    This view handles the process of generating a password reset token
    and sending a reset link to the user's registered email address.
    Rate limiting is applied to restrict the number of requests from the same IP address.
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
    """

    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

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

        # Get or create a KYC record for the user
        kyc, created = KYC.objects.get_or_create(user=user)

        # Initialize the serializer with the existing KYC data and the new data
        serializer = KYCSerializer(kyc, data=data, partial=True)

        if serializer.is_valid():
            serializer.save()  # Save the updated KYC data
            return Response({'message': 'KYC updated successfully', 'kyc': serializer.data}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  # Return validation errors if any


class UpdateVehicleInfoView(APIView):
    """
    API view for updating the user's vehicle information.

    This view allows authenticated users to update their vehicle details.
    If no vehicle record exists for the user, a new one is created.
    The view utilizes token-based authentication to ensure that only
    authenticated users can access this endpoint.
    """

    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

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

        # Get or create a vehicle record for the user
        vehicle, created = Vehicle.objects.get_or_create(user=user)

        # Initialize the serializer with the existing vehicle data and the new data
        serializer = VehicleSerializer(vehicle, data=data, partial=True)

        if serializer.is_valid():
            serializer.save()  # Save the updated vehicle data
            return Response({'message': 'Vehicle information updated successfully', 'vehicle': serializer.data},
                            status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  # Return validation errors if any


class UpdatePersonalInfoView(APIView):
    """
    API view for updating a user's personal information and social media links.

    This view allows authenticated users to update their personal information
    (excluding email) and their social media links. The view utilizes token-based
    authentication to ensure that only authenticated users can access this endpoint.
    """

    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        Handle POST requests for updating personal information.

        Args:
            request: The HTTP request object containing the user data and social media links to be updated.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            Response: A Response object containing the updated user and social media data,
                      or error messages if validation fails.
        """
        user = get_user_from_token(request)  # Retrieve the authenticated user
        social_media, created = SocialMediaLink.objects.get_or_create(user=user)

        # Update user data (excluding email)
        user_serializer = CustomUserSerializer(user, data=request.data, partial=True)
        social_media_serializer = SocialMediaLinkSerializer(social_media, data=request.data, partial=True)

        if user_serializer.is_valid() and social_media_serializer.is_valid():
            user_serializer.save()  # Save the updated user information
            social_media_serializer.save()  # Save the updated social media links
            return Response({
                'user': user_serializer.data,
                'social_media': social_media_serializer.data
            }, status=status.HTTP_200_OK)

        return Response({
            'user_errors': user_serializer.errors,
            'social_media_errors': social_media_serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)  # Return validation errors if any


class UpdateSubscriptionPlanView(APIView):
    """
    API view for updating a user's subscription plan.

    This view allows authenticated users to update their subscription plan
    based on the provided plan name. The view utilizes token-based
    authentication to ensure that only authenticated users can access this endpoint.
    """

    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

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
        subscription, created = Subscription.objects.get_or_create(user=user)

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
    """

    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

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
    """

    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

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
    permission_classes = [IsAuthenticated]

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
    permission_classes = [IsAuthenticated]

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
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PackageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PlaceBidView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, package_id):
        mover = get_user_from_token(request)
        price = request.data.get('price')

        if not price:
            return Response({"error": "Price is required to place a bid."}, status=400)

        package = Package.objects.get(id=package_id)

        # Create a new bid
        bid = Bid.objects.create(
            package=package,
            mover=mover,
            price=price
        )

        return Response({"message": "Bid placed successfully.", "bid_id": bid.id}, status=201)


class GetAllBidsView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

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
    permission_classes = [IsAuthenticated]

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
    permission_classes = [IsAuthenticated]

    def post(self, request, bid_id):
        try:
            user = get_user_from_token(request)
            # Retrieve the bid using the bid_id
            bid = Bid.objects.get(id=bid_id)

            # Ensure the user requesting the bid details is either the owner of the package or the mover who made the bid
            if bid.package.user != user and bid.mover != user:
                return Response({"error": "You are not authorized to view this bid."}, status=403)

            qr_code = QRCode()
            qr_code.save()
            PackageOffer.objects.create(package_bid=bid, qr_code=qr_code)

            return Response({"message": f"{bid.mover.email} has been selected for the delivery."},
                            status=200)

        except Bid.DoesNotExist:
            return Response({"error": "Bid not found."}, status=404)


class GetPackageOfferDetailView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

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
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

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
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

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
