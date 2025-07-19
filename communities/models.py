import uuid
from django.db import models
from users.models import User

class Community(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    avatar_url = models.URLField(blank=True, null=True)
    banner_url = models.URLField(blank=True, null=True)
    
    is_private = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_communities')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True, null=True)
    
    category = models.CharField(max_length=50, blank=True, null=True)
    tags = models.JSONField(default=list, blank=True)
    
    class Meta:
        db_table = 'communities'
        verbose_name = 'Comunidad'
        verbose_name_plural = 'Comunidades'
    
    def __str__(self):
        return self.name


class CommunityRole(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    name = models.CharField(max_length=50, unique=True)
    permissions = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'community_roles'
        verbose_name = 'Rol de Comunidad'
        verbose_name_plural = 'Roles de Comunidades'

    def __str__(self):
        return self.name


class CommunityMember(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    community = models.ForeignKey(Community, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='community_memberships')
    
    role = models.ForeignKey(CommunityRole, on_delete=models.CASCADE, related_name="members")
    joined_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'community_members'
        unique_together = ('community', 'user')
        indexes = [
            models.Index(fields=['community', 'user']),
        ]
        verbose_name = 'Miembro de la comunidad'
        verbose_name_plural = 'Miembros de comunidades'
    
    def __str__(self):
        return f"{self.user.username} - {self.community.name} ({self.role.name})"