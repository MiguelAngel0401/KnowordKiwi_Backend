from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.db.models import Count
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
    queryset = Community.objects.all()  # Ya filtra los borrados por el manager

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()  # get_object usa el queryset por defecto
        instance.deleted_at = timezone.now()
        instance.save()
        return Response(
            {"message": "Comunidad eliminada correctamente"},
            status=status.HTTP_204_NO_CONTENT,
        )

    @action(detail=False, methods=["get"], url_path="my-communities")
    def my_communities(self, request):
        """
        Devuelve las comunidades creadas por el usuario autenticado,
        incluyendo la cantidad de miembros de cada una.
        """
        user_communities = Community.objects.filter(created_by=request.user).annotate(
            member_count=Count("memberships")
        )
        page = self.paginate_queryset(user_communities)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(user_communities, many=True)
        return Response(serializer.data)


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
        # Asegurarse de que la comunidad no esté eliminada antes de listar sus miembros.
        community_id = self.kwargs.get("community_id")
        community = get_object_or_404(Community, id=community_id)
        return CommunityMember.objects.filter(community=community)


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
        # get_object_or_404 usará el manager por defecto, que ya filtra las comunidades eliminadas.
        community = get_object_or_404(Community.objects, id=community_id)

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
        # TODO: Considerar una forma más robusta de obtener el rol por defecto, en lugar de un nombre hardcodeado.
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
        Devuelve sugerencias de etiquetas basadas en la consulta de búsqueda del usuario.
        Busca etiquetas cuyo nombre contenga el texto de la consulta
        (insensible a mayúsculas/minúsculas).
        Si no hay consulta, devuelve las etiquetas más populares.
        """
        query = request.query_params.get("q", None)

        if query:
            # Limita a 10 sugerencias
            tags = Tag.objects.filter(name__icontains=query)[:10]
        else:
            # Si no hay consulta, devuelve las 10 etiquetas más usadas
            # en comunidades activas
            tags = (  # El filtro en communities ya es manejado por el manager
                Tag.objects.filter(communities__in=Community.objects.all())
                .annotate(community_count=Count("communities"))
                .order_by("-community_count")[:10]
            )
        serializer = TagSerializer(tags, many=True)
        return Response(serializer.data)


class ExploreCommunitiesView(APIView):
    """
    View para explorar comunidades agrupadas por etiqueta.
    """

    def get(self, request):
        # Obtenemos todas las etiquetas que tienen al menos una comunidad activa,
        # precargando eficientemente dichas comunidades.
        # Usamos prefetch_related con el manager por defecto de Community para eficiencia.
        active_communities_qs = Community.objects.prefetch_related("tags")
        tags_with_communities = (
            Tag.objects.filter(communities__in=active_communities_qs)
            .distinct()
            .prefetch_related("communities")
        )

        data = []
        for tag in tags_with_communities:
            # El manager ya se encarga de filtrar, no necesitamos la comprobación manual.
            active_communities = tag.communities.all()
            if active_communities:
                serialized = CommunitySerializer(active_communities, many=True)
                data.append({"tag": tag.name, "communities": serialized.data})

        return Response(data)


class CommunitiesByTagView(APIView):
    """
    View para obtener las comunidades asociadas a una etiqueta (tag) específica.
    """

    permission_classes = [permissions.AllowAny]  # Accesible públicamente

    def get(self, request, tag_name):
        """
        Devuelve una lista de comunidades que tienen la etiqueta especificada.
        La búsqueda de la etiqueta no distingue entre mayúsculas y minúsculas.
        """
        tag = get_object_or_404(Tag.objects, name__iexact=tag_name)

        communities = (  # El manager por defecto de Community se encarga del filtrado.
            tag.communities.all()
            .annotate(member_count=Count("memberships"))
            .order_by("-member_count")
        )

        serializer = CommunitySerializer(communities, many=True)
        return Response(serializer.data)
