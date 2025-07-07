from rest_framework import viewsets, generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.core.exceptions import PermissionDenied

from communities.permissions import IsCommunityCreator
from communities.services import join_community
from users.models import User
from .models import Community, CommunityMember, CommunityRole
#from .serializers import (
    #CommunitySerializer,
    #CommunityMemberSerializer,
#)
class CommunityViewSet(viewsets.ModelViewSet):
    """""""CRUD de comunidades"""""""
    queryset = Community.objects.all()
    #serializer_class = CommunitySerializer
    permission_classes = [permissions.IsAuthenticated, IsCommunityCreator] #solo el creador de la comunidad puede editarla o eliminarla

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user) #aqui el usuario que crea la comunidad
        
        
class CommunityMemberViewSet(viewsets.ModelViewSet):
    #serializer_class = CommunityMemberSerializer
    permission_classes = [permissions.IsAuthenticated] #miembros de la comunidad

    def get_queryset(self):
        community_id = self.kwargs.get("community_id")
        return CommunityMember.objects.filter(community_id=community_id)#aqui se filtran los miembros de la comunidad
    
    
class JoinCommunityView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, community_id):
        try:
            join_community(request.user, community_id)
            return Response({"message": "Te has unido a la comunidad"}, status=status.HTTP_201_CREATED)
        except PermissionDenied as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)#aqui un usuario se une a una comunidad
        
        
class CommunityFeedView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, community_id):
        community = get_object_or_404(Community, id=community_id)

        return Response({
            "message": f"Feed de la comunidad: {community.name}"
        }) #Feeds de las comunidades
