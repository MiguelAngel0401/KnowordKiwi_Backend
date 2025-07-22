from rest_framework import viewsets, status, generics, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from .models import UserRelationship
from .serializers import UserSerializer
from .service import SocialFollowService

User = get_user_model()

class FollowViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=True, methods=['post'])
    def follow(self, request, pk=None):
        try:
            user_to_follow = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response({"detail": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)

        if user_to_follow == request.user:
            return Response({"detail": "No puedes seguirte a ti mismo."}, status=status.HTTP_400_BAD_REQUEST)#seguir a los usurios
        

        try:
            relation = SocialFollowService.follow_user(request.user, user_to_follow)
            if relation:
                return Response({"detail": "Ahora sigues a este usuario."}, status=status.HTTP_201_CREATED)
            else:
                return Response({"detail": "Ya sigues a este usuario."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def unfollow(self, request, pk=None):
        try:
            user_to_unfollow = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response({"detail": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)

        success = SocialFollowService.unfollow_user(request.user, user_to_unfollow)
        if success:
            return Response({"detail": "Has dejado de seguir a este usuario."}, status=status.HTTP_200_OK)
        else:
            return Response({"detail": "No estabas siguiendo a este usuario."}, status=status.HTTP_400_BAD_REQUEST)
        #sejar de seguir a los usuarios

class FollowersListView(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user_id = self.kwargs['pk']
        return User.objects.filter(following__following__id=user_id)

class FollowingListView(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user_id = self.kwargs['pk']
        return User.objects.filter(followers__follower__id=user_id)
