from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils import timezone
from datetime import timedelta

from .models import CustomUser, OTP
from .serializers import CustomUserSerializer, OTPVerificationSerializer, TokenSerializer
from Profile.models import KYC, Vehicle, SubscriptionPlan, Subscription


def get_user_from_token(request):
    try:
        token = request.headers.get('Authorization', '').split(' ')[1]
        token = Token.objects.get(key=token)
        return token.user
    except Exception:
        raise AuthenticationFailed('Invalid token')


@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = CustomUser.objects.create(email=serializer.validated_data['email'])
                user.set_password(request.data.get('password'))
                user.save()

                KYC.objects.create(user=user)
                Vehicle.objects.create(user=user)
                free_plan, _ = SubscriptionPlan.objects.get_or_create(name="free")
                subscription = Subscription.objects.create(user=user, plan=free_plan)
                subscription.end_date = timezone.now().date() + timedelta(days=3)
                subscription.save()

                otp = OTP.objects.create(user=user)
                otp.send_otp()

                return Response(CustomUserSerializer(user).data, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_exempt, name='dispatch')
class VerifyOTPView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            otp = OTP.objects.get(user__email=request.data['email'], code=request.data['code'])
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if otp.is_used:
            return Response({'error': 'OTP has already been used'}, status=status.HTTP_400_BAD_REQUEST)

        if otp.is_expired():
            return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

        otp.is_used = True
        otp.user.is_email_verified = True
        otp.user.save()
        otp.save()

        return Response({'message': 'Email verified successfully'}, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class ResendOTPView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({'error': 'Invalid email or phone number'}, status=status.HTTP_400_BAD_REQUEST)

        otp = OTP.objects.create(user=user)
        otp.send_otp()

        return Response({'message': 'OTP sent to email'}, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(username=email, password=password)
        if user is None:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

        if not user.is_email_verified:
            return Response({'error': 'Email not verified'}, status=status.HTTP_400_BAD_REQUEST)

        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user': CustomUserSerializer(user).data
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    def post(self, request):
        try:
            request.user.auth_token.delete()
        except Exception:
            pass
        return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class ForgotPasswordRequestOTPView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        try:
            user = CustomUser.objects.get(email=email)
            otp = OTP.objects.create(user=user)
            otp.send_otp()
            return Response({'message': 'OTP sent to email'}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_exempt, name='dispatch')
class ResetPasswordView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        code = request.data.get('code')
        new_password = request.data.get('new_password')

        try:
            otp = OTP.objects.get(user__email=email, code=code)
            if otp.is_expired():
                return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)
            if otp.is_used:
                return Response({'error': 'OTP has already been used'}, status=status.HTTP_400_BAD_REQUEST)
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)
            user.set_password(new_password)
            user.save()
            otp.is_used = True
            otp.save()
            return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
