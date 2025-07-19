from rest_framework import viewsets, generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import get_object_or_404

from users.models import User
from .models import Community, CommunityMember, CommunityRole
from .serializers import (
    CommunitySerializer,
    CommunityMemberSerializer,
)
class CommunityViewSet(viewsets.ModelViewSet):
    """""""CRUD de comunidades"""""""
    queryset = Community.objects.all()
    serializer_class = CommunitySerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user) #aqui el usuario que crea la comunidad
        
        
class CommunityMemberViewSet(viewsets.ModelViewSet):
    serializer_class = CommunityMemberSerializer
    permission_classes = [permissions.IsAuthenticated] #miembros de la comunidad

    def get_queryset(self):
        community_id = self.kwargs.get("community_id")
        return CommunityMember.objects.filter(community_id=community_id)#aqui se filtran los miembros de la comunidad
    
    
class JoinCommunityView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, community_id):
        community = get_object_or_404(Community, id=community_id)

        member_exists = CommunityMember.objects.filter(
            user=request.user, community=community
        ).exists()

        if member_exists:
            return Response(
                {"message": "Ya eres miembro de esta comunidad"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        role = get_object_or_404(CommunityRole, name="member")

        CommunityMember.objects.create(
            user=request.user,
            community=community,
            role=role
        )

        return Response(
            {"message": "Te has unido a la comunidad"},
            status=status.HTTP_201_CREATED
        )#aqui un usuario se une a una comunidad
        
        
class CommunityFeedView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, community_id):
        community = get_object_or_404(Community, id=community_id)

        return Response({
            "message": f"Feed de la comunidad: {community.name}"
        }) #Feeds de las comunidades
        
class CommunityByCategoryView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, category):
        communities = Community.objects.filter(
            category__iexact=category,
            deleted_at__isnull=True  # Aseguramos que no se muestren comunidades eliminadas
            
            )
        serializer = CommunitySerializer(communities, many=True)
        return Response(serializer.data) #comunidades por categoria)
    
class CommunityDetailView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, community_id):
        community = get_object_or_404(Community, id=community_id)
        serializer = CommunitySerializer(community)
        return Response(serializer.data)
