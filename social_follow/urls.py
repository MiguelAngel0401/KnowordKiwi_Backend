from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import FollowViewSet, FollowersListView, FollowingListView

router = DefaultRouter()
router.register(r'follow', FollowViewSet, basename='follow')

urlpatterns = [
    # Listar seguidores de un usuario
    path('followers/<uuid:pk>/', FollowersListView.as_view(), name='followers-list'),
    
    # Listar a quién sigue un usuario
    path('following/<uuid:pk>/', FollowingListView.as_view(), name='following-list'),
]

urlpatterns += router.urls
