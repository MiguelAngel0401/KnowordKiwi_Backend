from rest_framework import permissions
from .models import CommunityMember

class IsCommunityMember(permissions.BasePermission): #Esto es para que solo usuarios regristados se unan

    def has_permission(self, request, view):  
        community_id = view.kwargs.get('community_id')
        if not community_id:
            return False
        return CommunityMember.objects.filter(
            community_id=community_id,
            user=request.user
        ).exists()

class IsCommunityModerator(permissions.BasePermission): #Esto es solo para los moderadores de las supercomunidades

    def permission(self, request, view):
        community_id = view.kwargs.get('community_id')
        if not community_id:
            return False

        member = CommunityMember.objects.filter(
            community_id=community_id,
            user=request.user
        ).select_related('role').first()

        if not member:
            return False

        return member.role.permissions.get('can_moderate', True)
    
class IsCommunityCreator(permissions.BasePermission):
    """
    Permite solo al creador de la comunidad editarla o eliminarla.
    """

    def has_object_permission(self, request, view, obj):
        # Métodos de solo lectura siempre permitidos
        if request.method in permissions.SAFE_METHODS:
            return True

        # Solo el creador puede editar/eliminar
        return obj.created_by == request.use
