from rest_framework import viewsets, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db.models import Count

from .models import Post
from .serializers import PostSerializer, PostDetailSerializer,FeedPostSerializer

from .permissions import IsAuthorOrReadOnly
from .services import PostService, FeedService

class PostViewSet(viewsets.ModelViewSet):
    queryset = Post.objects.all()
    
    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return PostSerializer
        return PostDetailSerializer #aqui se usa el serializer para crear actualizar etc
    
    def get_permissions(self):
        if self.action in ['update', 'partial_update', 'destroy']:
            return [permissions.IsAuthenticated(), IsAuthorOrReadOnly()]
        return [permissions.IsAuthenticatedOrReadOnly()] #solo los autores pueden hacer las modificacioens
    
    
class FeedView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        feed_posts = FeedService.get_user_feed(request.user)
        serializer = FeedPostSerializer(feed_posts, many=True)
        return Response(serializer.data) #aqui los usuarios ven su feed ojo solo ellos
    
class TrendingPostsView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    serializer_class = FeedPostSerializer#cualquiera ve los posts

    def get_queryset(self):
        return Post.objects.annotate(comment_count=Count('comments')).order_by('-comment_count')[:10]#los 10 +
    
class MyPostsView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = FeedPostSerializer#aqui solo usuario autenticados ve sus posts

    def get_queryset(self):
        return PostService.get_user_posts(self.request.user)