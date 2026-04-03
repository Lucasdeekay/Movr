from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication

from django.core.files.uploadedfile import InMemoryUploadedFile

from Auth.views import get_user_from_token
from .models import KYC, Vehicle, SubscriptionPlan, Subscription, Notification, SocialMediaLink
from .serializers import (
    KYCSerializer, VehicleSerializer, SubscriptionSerializer, 
    NotificationSerializer, SocialMediaLinkSerializer
)
from wallet.services import create_dedicated_account_for_user


class UpdateKYCView(APIView):
    """
    API view for updating the user's KYC (Know Your Customer) information.
    
    This view allows authenticated users to update their KYC details.
    If no KYC record exists for the user, a new one is created.
    
    Endpoint: POST /profile/v1/update-kyc/
    
    Request Body:
        {
            "bvn": "12345678901",
            "nin": "12345678901",
            "driver_license": <file>
        }
    
    Response (200):
        {
            "message": "KYC updated successfully",
            "kyc": {...}
        }
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Handle POST requests for updating KYC information."""
        user = get_user_from_token(request)
        data = request.data
        
        if 'bvn' not in data or 'nin' not in data:
            return Response(
                {'error': 'Both BVN and NIN are required fields.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if len(str(data.get('bvn', ''))) != 11 or len(str(data.get('nin', ''))) != 11:
            return Response(
                {'error': 'Both BVN and NIN must be exactly 11 digits.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        kyc, created = KYC.objects.get_or_create(user=user)
        
        if 'driver_license' in data:
            driver_license = data['driver_license']
            if isinstance(driver_license, InMemoryUploadedFile):
                if not driver_license.content_type.startswith('image'):
                    return Response(
                        {'error': 'Driver license must be an image file.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                if driver_license.size > 5 * 1024 * 1024:
                    return Response(
                        {'error': 'Driver license image size must be under 5MB.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
        
        serializer = KYCSerializer(kyc, data=data, partial=True, context={'request': request})
        create_dedicated_account_for_user(user)
        
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'KYC updated successfully', 'kyc': serializer.data}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateVehicleInfoView(APIView):
    """
    API view for updating the user's vehicle information.
    
    This view allows authenticated users to update their vehicle details.
    If no vehicle record exists for the user, a new one is created.
    
    Endpoint: POST /profile/v1/update-vehicle/
    
    Request Body:
        {
            "vehicle_plate_number": "XYZ987ABC",
            "vehicle_type": "Truck",
            "vehicle_brand": "Ford",
            "vehicle_color": "Blue"
        }
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Handle POST requests for updating vehicle information."""
        user = get_user_from_token(request)
        data = request.data
        
        if 'vehicle_plate_number' not in data or 'vehicle_type' not in data:
            return Response(
                {'error': 'Both vehicle_plate_number and vehicle_type are required fields.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if data.get('vehicle_plate_number') and len(data['vehicle_plate_number']) < 4:
            return Response(
                {'error': 'Vehicle plate number must be at least 4 characters long.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        vehicle, created = Vehicle.objects.get_or_create(user=user)
        
        image_fields = ['vehicle_photo', 'driver_license', 'vehicle_inspector_report', 'vehicle_insurance']
        for field in image_fields:
            if field in data:
                image_file = data[field]
                if image_file and isinstance(image_file, InMemoryUploadedFile):
                    if not image_file.content_type.startswith('image'):
                        return Response(
                            {'error': f'{field} must be an image file.'},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    if image_file.size > 5 * 1024 * 1024:
                        return Response(
                            {'error': f'{field} image size must be under 5MB.'},
                            status=status.HTTP_400_BAD_REQUEST
                        )
        
        serializer = VehicleSerializer(vehicle, data=data, partial=True, context={'request': request})
        
        if serializer.is_valid():
            serializer.save()
            return Response(
                {'message': 'Vehicle information updated successfully', 'vehicle': serializer.data},
                status=status.HTTP_200_OK
            )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfileImageUploadView(APIView):
    """
    API view for uploading user profile image.
    
    This view allows authenticated users to upload or update their profile picture.
    
    Endpoint: POST /profile/v1/upload-profile-image/
    
    Request Body:
        {
            "profile_picture": <file>
        }
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Handle POST requests for uploading profile image."""
        user = get_user_from_token(request)
        
        if 'profile_picture' not in request.FILES:
            return Response(
                {'error': 'No profile picture provided.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        profile_picture = request.FILES['profile_picture']
        
        if not profile_picture.content_type.startswith('image'):
            return Response(
                {'error': 'Profile picture must be an image file.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if profile_picture.size > 5 * 1024 * 1024:
            return Response(
                {'error': 'Profile picture size must be under 5MB.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.profile_picture = profile_picture
        user.save()
        
        return Response(
            {'message': 'Profile picture uploaded successfully', 'profile_picture': user.profile_picture.url},
            status=status.HTTP_200_OK
        )


class UpdatePersonalInfoView(APIView):
    """
    API view for updating user's personal information.
    
    This view allows authenticated users to update their first name, last name, and phone number.
    
    Endpoint: POST /profile/v1/update-personal-info/
    
    Request Body:
        {
            "first_name": "John",
            "last_name": "Doe",
            "phone_number": "+2348012345678"
        }
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Handle POST requests for updating personal information."""
        user = get_user_from_token(request)
        data = request.data
        
        if 'first_name' in data:
            user.first_name = data['first_name']
        if 'last_name' in data:
            user.last_name = data['last_name']
        if 'phone_number' in data:
            user.phone_number = data['phone_number']
        
        user.save()
        
        return Response(
            {'message': 'Personal information updated successfully'},
            status=status.HTTP_200_OK
        )


class UpdateSubscriptionPlanView(APIView):
    """
    API view for updating user's subscription plan.
    
    This view allows authenticated users to upgrade or change their subscription plan.
    
    Endpoint: POST /profile/v1/update-subscription/
    
    Request Body:
        {
            "plan_name": "basic"
        }
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Handle POST requests for updating subscription plan."""
        user = get_user_from_token(request)
        data = request.data
        
        if 'plan_name' not in data:
            return Response(
                {'error': 'Plan name is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            plan = SubscriptionPlan.objects.get(name=data['plan_name'])
        except SubscriptionPlan.DoesNotExist:
            return Response(
                {'error': 'Invalid plan name.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        subscription, created = Subscription.objects.get_or_create(
            user=user,
            defaults={'plan': plan}
        )
        
        if not created:
            subscription.plan = plan
            subscription.save()
        
        return Response(
            {'message': 'Subscription updated successfully', 'plan': plan.name},
            status=status.HTTP_200_OK
        )


class GetNotificationsView(APIView):
    """
    API view for retrieving user's notifications.
    
    This view allows authenticated users to get their notifications.
    
    Endpoint: GET /profile/v1/notifications/
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Handle GET requests for retrieving notifications."""
        user = get_user_from_token(request)
        notifications = Notification.objects.filter(user=user)
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class MarkNotificationAsReadView(APIView):
    """
    API view for marking a notification as read.
    
    Endpoint: POST /profile/v1/notifications/<uuid>/mark-read/
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, notification_id):
        """Handle POST requests for marking notification as read."""
        user = get_user_from_token(request)
        
        try:
            notification = Notification.objects.get(id=notification_id, user=user)
        except Notification.DoesNotExist:
            return Response(
                {'error': 'Notification not found.'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        notification.is_read = True
        notification.save()
        
        return Response(
            {'message': 'Notification marked as read.'},
            status=status.HTTP_200_OK
        )


class UpdateSocialMediaLinkView(APIView):
    """
    API view for updating user's social media links.
    
    Endpoint: POST /profile/v1/social-media/
    
    Request Body:
        {
            "facebook": "https://facebook.com/user",
            "instagram": "https://instagram.com/user",
            "linkedin": "https://linkedin.com/in/user"
        }
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Handle POST requests for updating social media links."""
        user = get_user_from_token(request)
        data = request.data
        
        social_link, created = SocialMediaLink.objects.get_or_create(user=user)
        serializer = SocialMediaLinkSerializer(social_link, data=data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response(
                {'message': 'Social media links updated successfully', 'data': serializer.data},
                status=status.HTTP_200_OK
            )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)