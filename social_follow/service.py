from django.db import IntegrityError
from django.core.exceptions import ValidationError
from users.models import User
from .models import UserRelationship

class SocialFollowService:
    @staticmethod
    def follow_user(follower: User, following: User) -> UserRelationship:
        "Aqui permitira que un usuario siga a otro"
        if follower == following:
            raise ValidationError("Un usuario no puede seguirse a sí mismo.")
        
        try:
            relationship, created = UserRelationship.objects.get_or_create(
                follower=follower,
                following=following
            )
            return relationship if created else None
        except IntegrityError:
            raise ValidationError("Ya existe la realcion de seguimiento")
    
    @staticmethod
    def unfollow_user(follower: User, following: User) -> bool:
        """Aqui permitira que un usuario deje de seguir a otro"""
        deleted, _ = UserRelationship.objects.filter(
            follower=follower,
            following=following
        ).delete()
        return bool(deleted)
    
    @staticmethod
    def is_following(follower: User, following: User) -> bool:
        """Aqui permitira que un usuario verifique si sigue a otro"""
        return UserRelationship.objects.filter(
            follower=follower,
            following=following
        ).exists()

    @staticmethod
    def get_followers(user: User) -> list[User]:
        """Aqui permitira que un usuario obtenga sus seguidores"""
        return list(UserRelationship.objects.filter(following=user).values_list('follower', flat=True))
    
    @staticmethod
    def get_following(user: User):
        """Aqui permitira que un usuario obtenga los usuarios que sigue"""
        return list(UserRelationship.objects.filter(follower=user).values_list('following', flat=True))
    
    