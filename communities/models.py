import uuid
from django.db import models
from django.core.exceptions import ValidationError
from users.models import User

class Community(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    avatar_url = models.URLField(blank=True, null=True)
    banner_url = models.URLField(blank=True, null=True)
    
    is_private = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_communities')
    
    cretaed_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True, null=True) # para eliminar 
    
    class Meta:
        db_table = 'communities'
        verbose_name = 'Comunidad'
        verbose_name_plural = 'Comunidades'
        
    def __str__(self):
        return self

class CommunityMember(models.Model):
    ROLW_CHOICES = [
        ('meber', 'Member'),
        ('admin', 'Admin'),
        ('moderator', 'Moderator'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    Community = models.ForeignKey(Community, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='community_memberships')
    
    role = models.CharField(max_length=20, choices=ROLW_CHOICES, default='member')
    joided_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'community_members'
        unique_together = ('community', 'user')
        indexes = [
            models.Index(fields=['community', 'user']),
        ]
        verbose_name = 'Miembro de la comunidad'
        verbose_name_plural = 'Miembros de comunidades'
        
    def __str__(self):
        return f"{self.user.username} - {self.community.name}"
    
    
