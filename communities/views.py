from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.utils import timezone

from users.authentication import CookieJWTAuthentication
from .models import Community, CommunityMember, CommunityRole, Tag
from .serializers import CommunityMemberSerializer, CommunitySerializer, TagSerializer


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
    """
    ViewSet para gestionar los miembros de una comunidad.

    Permite listar, crear, actualizar y eliminar miembros asociados a una comunidad específica.
    El queryset se filtra por el identificador de la comunidad recibido en los parámetros de la URL.

    Autenticación:
    - Requiere autenticación mediante CookieJWTAuthentication.
    - Solo usuarios autenticados pueden acceder a estos endpoints.

    Métodos principales:
    - get_queryset(): Filtra los miembros por el ID de la comunidad proporcionado en la URL.
    """

    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CommunityMemberSerializer

    def get_queryset(self):
        community_id = self.kwargs.get("community_id")
        return CommunityMember.objects.filter(community_id=community_id)


class JoinCommunityView(APIView):
    """
    View para que un usuario se una a una comunidad específica.
    Permite a un usuario autenticado unirse a una comunidad.
    Si el usuario ya es miembro, devuelve un mensaje de error.
    Autenticación:
    - Requiere autenticación mediante CookieJWTAuthentication.
    - Solo usuarios autenticados pueden acceder a estos endpoints.
    """

    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, community_id):
        """
        Permite a un usuario autenticado unirse a una comunidad.
        Si el usuario ya es miembro, devuelve un mensaje de error.
        """
        community = get_object_or_404(Community, id=community_id)

        member_exists = CommunityMember.objects.filter(
            user=request.user, community=community
        ).exists()

        if member_exists:
            return Response(
                {"message": "Ya eres miembro de esta comunidad"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Asignar rol de miembro por defecto
        # Se asume que existe un rol llamado "Member" en la base de datos.
        role = get_object_or_404(CommunityRole, name="Member")

        CommunityMember.objects.create(
            user=request.user, community=community, role=role
        )

        return Response(
            {"message": "Te has unido a la comunidad"}, status=status.HTTP_201_CREATED
        )


class CommunityFeedView(APIView):
    """
    View para obtener el feed de una comunidad específica.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, community_id):
        """
        Devuelve el feed de la comunidad especificada por community_id.
        Se asume que el feed es una lista de publicaciones o actividades recientes.
        """
        community = get_object_or_404(Community, id=community_id)

        return Response({"message": f"Feed de la comunidad: {community.name}"})


class TagSuggestionView(APIView):
    """View para sugerencias de etiquetas. Usado en la creación de comunidades."""

    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """
        Devuelve sugerencias de etiquetas basadas en la consulta del usuario.
        Si no hay consulta, devuelve las etiquetas más populares.
        """

        query = request.query_params.get("q", "")
        if query:
            tags = Tag.objects.filter(name__icontains=query)[:5]  # Limita sugerencias
        else:
            tags = Tag.objects.all()[:10]  # O las más populares
        serializer = TagSerializer(tags, many=True)
        return Response(serializer.data)
