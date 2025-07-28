from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    CommunitiesByTagView,
    CommunityViewSet,
    CommunityMemberViewSet,
    JoinCommunityView,
    CommunityFeedView,
    TagSuggestionView,
    ExploreCommunitiesView,
)

# ruta del view set

router = DefaultRouter()
# Operaciones CRUD para las comunidades
# Permite listar, crear, actualizar y eliminar comunidades con borrado lógico.
router.register(r"communities", CommunityViewSet, basename="community")

urlpatterns = [
    path("", include(router.urls)),
    # Esta ruta permite acceder a los miembros de una comunidad específica.
    # Tambien permite crear nuevos miembros.
    path(
        "communities/<uuid:community_id>/members/",
        CommunityMemberViewSet.as_view({"get": "list", "post": "create"}),
        name="community-members-created",
    ),
    # Esta ruta permite acceder a los miembros de una comunidad específica
    # y realizar operaciones get, put y delete.
    # Se utiliza el UUID de la comunidad para filtrar los miembros.
    # Se usa la llave primaria (pk) de la tabla community_members para operaciones específicas.
    path(
        "communities/<uuid:community_id>/members/<uuid:pk>/",
        CommunityMemberViewSet.as_view(
            {"get": "retrieve", "put": "update", "delete": "destroy"}
        ),
        name="community-member-detail",
    ),
    # Ruta para unirse a una comunidad específica.
    # Permite a un usuario autenticado unirse a una comunidad. A diferencia del endpoint anterior,
    # este endpoint no requiere un ID de miembro específico.
    path(
        "communities/<uuid:community_id>/join/",
        JoinCommunityView.as_view(),
        name="join-community",
    ),
    path(
        "communities/<uuid:community_id>/feed/",
        CommunityFeedView.as_view(),
        name="community-feed",
    ),
    # Ruta para sugerencias de etiquetas en comunidades.
    # Permite obtener sugerencias de etiquetas basadas en las etiquetas existentes.
    # Se usa en el apartado de creación y actualización de comunidades.
    path(
        "communities/tags/suggestions/",
        TagSuggestionView.as_view(),
        name="tag-suggestions",
    ),
    path(
        "explore/",
        ExploreCommunitiesView.as_view(),
        name="explore-communities",
    ),
    path(
        "communities/tag/<str:tag_name>/",
        CommunitiesByTagView.as_view(),
        name="communities-by-tag",
    ),
]
