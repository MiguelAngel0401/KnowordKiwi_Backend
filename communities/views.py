from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.utils import timezone

from users.authentication import CookieJWTAuthentication
from .models import Community, CommunityMember, CommunityRole, Tag
from .serializers import CommunitySerializer, TagSerializer


class CommunityViewSet(viewsets.ModelViewSet):
    """
    ViewSet para manejar las comunidades.
    Permite listar, crear, actualizar y eliminar comunidades con borrado logico.
    """

    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = CommunitySerializer
    queryset = Community.objects.filter(deleted_at__isnull=True)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.deleted_at = timezone.now()
        instance.save()
        return Response(
            {"message": "Comunidad eliminada correctamente"},
            status=status.HTTP_204_NO_CONTENT,
        )


class CommunityMemberViewSet(viewsets.ModelViewSet):
    # serializer_class = CommunityMemberSerializer
    permission_classes = [permissions.IsAuthenticated]  # miembros de la comunidad

    def get_queryset(self):
        community_id = self.kwargs.get("community_id")
        return CommunityMember.objects.filter(
            community_id=community_id
        )  # aqui se filtran los miembros de la comunidad


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
            user=request.user, community=community, role=role
        )

        return Response(
            {"message": "Te has unido a la comunidad"}, status=status.HTTP_201_CREATED
        )  # aqui un usuario se une a una comunidad


class CommunityFeedView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, community_id):
        community = get_object_or_404(Community, id=community_id)

        return Response(
            {"message": f"Feed de la comunidad: {community.name}"}
        )  # Feeds de las comunidades


class TagSuggestionView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        query = request.query_params.get("q", "")
        if query:
            tags = Tag.objects.filter(name__icontains=query)[:5]  # Limita sugerencias
        else:
            tags = Tag.objects.all()[:10]  # O las más populares
        serializer = TagSerializer(tags, many=True)
        return Response(serializer.data)
