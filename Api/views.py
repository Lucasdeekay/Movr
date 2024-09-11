from datetime import timedelta

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from django.core.mail import send_mail
from .models import CustomUser, KYC, Vehicle, SubscriptionPlan, Subscription, OTP, SocialMediaLink
from .serializers import CustomUserSerializer, OTPVerificationSerializer, TokenSerializer, VehicleSerializer, \
    KYCSerializer, SocialMediaLinkSerializer
from rest_framework.authtoken.models import Token
import random


class RegisterView(APIView):
    @csrf_exempt
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    def post(self, request, *args, **kwargs):
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
                free_plan = SubscriptionPlan.objects.get(name="Free")
                Subscription.objects.create(user=user, plan=free_plan)

                # Generate and send OTP for email verification
                otp = OTP.objects.create(user=user)
                otp.send_otp()

                return Response(CustomUserSerializer(user).data, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    @csrf_exempt
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    def post(self, request, *args, **kwargs):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                otp = OTP.objects.get(
                    user__email=serializer.validated_data['email'],
                    code=serializer.validated_data['code']
                )
            except OTP.DoesNotExist:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

            if otp.is_used:
                return Response({'error': 'OTP has already been used'}, status=status.HTTP_400_BAD_REQUEST)

            if otp.is_expired():
                return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

            # Mark OTP as used and verify user
            otp.is_used = True
            otp.user.is_email_verified = True
            otp.user.save()
            otp.save()

            return Response({'message': 'Email verified successfully'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    @csrf_exempt
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    def post(self, request, *args, **kwargs):
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
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Retrieve the token for the authenticated user
        try:
            logout(request.user)
            token = Token.objects.get(user=request.user)
            # Delete the token to log out the user
            token.delete()
            return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        except Token.DoesNotExist:
            return Response({"detail": "Invalid token or user already logged out."}, status=status.HTTP_400_BAD_REQUEST)


class ForgotPasswordRequestOTPView(APIView):
    @csrf_exempt
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')

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
        message = f"Hello {user.first_name},\n\nClick the link below to reset your password:\n\n{reset_link}\n\nIf you did not request a password reset, please ignore this email."
        send_mail(subject, message, 'no-reply@yourapp.com', [user.email])

        return Response({'message': 'Password reset link sent to email'}, status=status.HTTP_200_OK)


class ResetPasswordView(APIView):
    @csrf_exempt
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    def post(self, request, *args, **kwargs):
        uid = request.data.get('uid')
        token = request.data.get('token')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        if new_password != confirm_password:
            return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

        try:
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
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        data = request.data

        kyc, created = KYC.objects.get_or_create(user=user)
        serializer = KYCSerializer(kyc, data=data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'KYC updated successfully', 'kyc': serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateVehicleInfoView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        data = request.data

        vehicle, created = Vehicle.objects.get_or_create(user=user)
        serializer = VehicleSerializer(vehicle, data=data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Vehicle information updated successfully', 'vehicle': serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdatePersonalInfoView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        social_media, created = SocialMediaLink.objects.get_or_create(user=user)

        # Update user data (excluding email)
        user_serializer = CustomUserSerializer(user, data=request.data, partial=True)
        social_media_serializer = SocialMediaLinkSerializer(social_media, data=request.data, partial=True)

        if user_serializer.is_valid() and social_media_serializer.is_valid():
            user_serializer.save()
            social_media_serializer.save()
            return Response({
                'user': user_serializer.data,
                'social_media': social_media_serializer.data
            }, status=status.HTTP_200_OK)

        return Response({
            'user_errors': user_serializer.errors,
            'social_media_errors': social_media_serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class UpdateSubscriptionPlanView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        plan_name = request.data.get('plan_name')

        if not plan_name:
            return Response({"error": "Plan name is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            plan = SubscriptionPlan.objects.get(name=plan_name.lower())
        except SubscriptionPlan.DoesNotExist:
            return Response({"error": "Subscription plan not found."}, status=status.HTTP_404_NOT_FOUND)

        subscription, created = Subscription.objects.get_or_create(user=request.user)

        # Calculate new end date based on the duration of the plan
        subscription.plan = plan
        subscription.start_date = timezone.now()
        subscription.end_date = subscription.start_date + timedelta(days=plan.duration)
        subscription.save()

        return Response({"message": "Subscription plan updated successfully."}, status=status.HTTP_200_OK)
