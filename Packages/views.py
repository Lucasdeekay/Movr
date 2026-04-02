from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from drf_spectacular.utils import extend_schema, OpenApiExample
from django.db import models
from django.utils import timezone

from Auth.views import get_user_from_token
from .models import Package, Bid, PackageOffer, QRCode
from .serializers import PackageSerializer, BidSerializer, PackageOfferSerializer


class PackageSubmissionView(APIView):
    """API view for submitting a package for delivery."""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=PackageSerializer,
        responses={201: PackageSerializer, 400: dict},
        tags=['Packages'],
        examples=[
            OpenApiExample('Submit Package', value={
                'location': 'Lagos',
                'destination': 'Abuja',
                'package_type': 'Delivery',
                'item_description': 'Electronics',
                'item_weight': 'medium',
                'receiver_name': 'John Doe',
                'receiver_phone_number': '+2348012345678',
                'range_radius': '10.00'
            }, request_only=True)
        ]
    )
    def post(self, request):
        user = get_user_from_token(request)
        serializer = PackageSerializer(data=request.data)
        if serializer.is_valid():
            package = serializer.save(user=user)
            
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            channel_layer = get_channel_layer()
            
            async_to_sync(channel_layer.group_send)(
                "all_movers",
                {
                    "type": "ride_request",
                    "package_id": str(package.id),
                    "location": package.location,
                    "destination": package.destination,
                }
            )
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PlaceBidView(APIView):
    """API view for placing a bid on a package."""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=BidSerializer,
        responses={201: BidSerializer, 400: dict},
        tags=['Packages'],
    )
    def post(self, request, package_id):
        user = get_user_from_token(request)
        try:
            package = Package.objects.get(id=package_id)
        except Package.DoesNotExist:
            return Response({'error': 'Package not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = BidSerializer(data=request.data)
        if serializer.is_valid():
            bid = serializer.save(package=package, bidder=user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetAllBidsView(APIView):
    """API view for getting all bids for a package."""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: BidSerializer(many=True)},
        tags=['Packages'],
    )
    def get(self, request, package_id):
        get_user_from_token(request)
        try:
            bids = Bid.objects.filter(package_id=package_id)
            serializer = BidSerializer(bids, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Package.DoesNotExist:
            return Response({'error': 'Package not found'}, status=status.HTTP_404_NOT_FOUND)


class GetBidDetailView(APIView):
    """API view for getting bid detail."""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: BidSerializer, 404: dict},
        tags=['Packages'],
    )
    def get(self, request, bid_id):
        get_user_from_token(request)
        try:
            bid = Bid.objects.get(id=bid_id)
            serializer = BidSerializer(bid)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Bid.DoesNotExist:
            return Response({'error': 'Bid not found'}, status=status.HTTP_404_NOT_FOUND)


class SelectMoverView(APIView):
    """API view for selecting a mover (accepting a bid)."""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={201: PackageOfferSerializer, 400: dict, 404: dict},
        tags=['Packages'],
    )
    def post(self, request, bid_id):
        user = get_user_from_token(request)
        try:
            bid = Bid.objects.get(id=bid_id)
            package = bid.package
            
            if package.user != user:
                return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)
            
            bid.is_accepted = True
            bid.save()
            
            package_offer = PackageOffer.objects.create(
                package=package,
                bid=bid,
                driver=bid.bidder,
                agreed_amount=bid.amount
            )
            
            package.status = 'accepted'
            package.save()
            
            serializer = PackageOfferSerializer(package_offer)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        except Bid.DoesNotExist:
            return Response({'error': 'Bid not found'}, status=status.HTTP_404_NOT_FOUND)


class GetAllPackageOffersView(APIView):
    """API view for getting all package offers."""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: PackageOfferSerializer(many=True)},
        tags=['Packages'],
    )
    def get(self, request):
        user = get_user_from_token(request)
        offers = PackageOffer.objects.filter(
            models.Q(package__user=user) | models.Q(driver=user)
        )
        serializer = PackageOfferSerializer(offers, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class GetPackageOfferDetailView(APIView):
    """API view for getting package offer detail."""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: PackageOfferSerializer, 404: dict},
        tags=['Packages'],
    )
    def get(self, request, package_offer_id):
        user = get_user_from_token(request)
        try:
            offer = PackageOffer.objects.get(id=package_offer_id)
            if offer.package.user != user and offer.driver != user:
                return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)
            serializer = PackageOfferSerializer(offer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except PackageOffer.DoesNotExist:
            return Response({'error': 'Package offer not found'}, status=status.HTTP_404_NOT_FOUND)


class PickupConfirmationView(APIView):
    """API view for confirming package pickup."""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: dict, 404: dict},
        tags=['Packages'],
    )
    def post(self, request, package_offer_id):
        user = get_user_from_token(request)
        try:
            offer = PackageOffer.objects.get(id=package_offer_id, driver=user)
        except PackageOffer.DoesNotExist:
            return Response({'error': 'Package offer not found'}, status=status.HTTP_404_NOT_FOUND)
        
        offer.picked_up = True
        offer.picked_up_at = timezone.now()
        offer.save()
        
        offer.package.status = 'in_transit'
        offer.package.save()
        
        return Response({'message': 'Package marked as picked up'}, status=status.HTTP_200_OK)


class DeliveryConfirmationView(APIView):
    """API view for confirming delivery."""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: dict, 404: dict},
        tags=['Packages'],
    )
    def post(self, request, package_offer_id):
        user = get_user_from_token(request)
        try:
            offer = PackageOffer.objects.get(id=package_offer_id, driver=user)
        except PackageOffer.DoesNotExist:
            return Response({'error': 'Package offer not found'}, status=status.HTTP_404_NOT_FOUND)
        
        offer.delivered = True
        offer.delivered_at = timezone.now()
        offer.save()
        
        offer.package.status = 'delivered'
        offer.package.save()
        
        return Response({'message': 'Package marked as delivered'}, status=status.HTTP_200_OK)


class PickedUpPackageOffersView(APIView):
    """API view for getting picked up offers."""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: PackageOfferSerializer(many=True)},
        tags=['Packages'],
    )
    def get(self, request):
        user = get_user_from_token(request)
        offers = PackageOffer.objects.filter(driver=user, picked_up=True, delivered=False)
        serializer = PackageOfferSerializer(offers, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ScheduledPackageOffersView(APIView):
    """API view for getting scheduled offers."""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: PackageOfferSerializer(many=True)},
        tags=['Packages'],
    )
    def get(self, request):
        user = get_user_from_token(request)
        offers = PackageOffer.objects.filter(driver=user, picked_up=False)
        serializer = PackageOfferSerializer(offers, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CancelPackageOfferView(APIView):
    """API view for cancelling a package offer."""
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=dict,
        responses={200: dict, 400: dict, 404: dict},
        tags=['Packages'],
    )
    def post(self, request, pk):
        user = get_user_from_token(request)
        try:
            offer = PackageOffer.objects.get(id=pk)
        except PackageOffer.DoesNotExist:
            return Response({'error': 'Package offer not found'}, status=status.HTTP_404_NOT_FOUND)
        
        if offer.package.user != user and offer.driver != user:
            return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)
        
        offer.is_cancelled = True
        offer.cancelled_at = timezone.now()
        offer.cancellation_reason = request.data.get('reason', '')
        offer.save()
        
        return Response({'message': 'Package offer cancelled'}, status=status.HTTP_200_OK)