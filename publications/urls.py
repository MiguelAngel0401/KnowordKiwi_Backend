from django.urls import path, include
from rest_framework import DefaultRouter
from .views import PostViewSet, FeedView, TrendingPostsView, MyPostsView

router = DefaultRouter()
router.register(r'posts', PostViewSet, basename='post')

urlpatterns = [
    path('', include(router.urls)),
    path('feed/', FeedView.as_view(), name='feed'),
    path('trending/', TrendingPostsView.as_view(), name='trending-posts'),
    path('my-posts/', MyPostsView.as_view(), name='my-posts'),
]
