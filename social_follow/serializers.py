from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import UserRelationship

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email'] #Aqui los campos que muestra del usuario


class UserRelationshipSerializer(serializers.ModelSerializer):
    follower = UserSerializer(read_only=True)  # Usuario que sigue a otro
    following = UserSerializer(read_only=True) # Usuario que está siendo seguido
    created_at = serializers.DateTimeField(read_only=True)  # Fecha en que se creó el seguimiento

    class Meta:
        model = UserRelationship
        fields = ['id', 'follower', 'following', 'created_at']