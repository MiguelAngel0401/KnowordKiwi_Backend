from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    CommunityViewSet, 
    CommunityMemberViewSet, 
    JoinCommunityView, 
    CommunityFeedView,
    CommunityByCategoryView,
    CommunityDetailView,
    
    )

#ruta del view set

router = DefaultRouter()
router.register(r'communities', CommunityViewSet, basename='community')

#ruta de la app de las comunidades y miembros de las mismas
urlpatterns = [
    path('', include(router.urls)),
    path('communities/<uuid:community_id>/members/', CommunityMemberViewSet.as_view({'get': 'list','post':'create'}), name='community-members-created'),
    path('communities/<uuid:community_id>/members/<uuid:pk>/',CommunityMemberViewSet.as_view(
        {'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='community-member-detail'),
    #ruta para unirse a una comunidad y el feed de la misma
    path('communities/<uuid:community_id>/join/', JoinCommunityView.as_view(), name='join-community'),
    path('communities/<uuid:community_id>/feed/', CommunityFeedView.as_view(), name='community-feed'),
    path('communities/category/<str:category>/', CommunityByCategoryView.as_view(), name='community-by-category'),
    path('communities/<uuid:community_id>/', CommunityDetailView.as_view(), name='community-detail'),
    
]
