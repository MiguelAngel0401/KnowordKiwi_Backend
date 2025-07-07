from django.shortcuts import get_object_or_404
from django.core.exceptions import PermissionDenied
from django.utils import timezone

from .models import Community, CommunityMember, CommunityRole


# === CRUD de comunidades ===

def create_community(user, data):
    return Community.objects.create(created_by=user, **data)

def update_community(user, community_id, data):
    community = get_object_or_404(Community, id=community_id)
    if community.created_by != user:
        raise PermissionDenied("Solo el creador puede editar esta comunidad.")
    
    for field in ['name', 'description', 'avatar_url', 'banner_url', 'is_private']:
        if field in data:
            setattr(community, field, data[field])

    community.save()
    return community

def delete_community(user, community_id):
    community = get_object_or_404(Community, id=community_id)
    if community.created_by != user:
        raise PermissionDenied("Solo el creador puede eliminar esta comunidad.")

    community.deleted_at = timezone.now()
    community.save()
    return community


# === Lógica de miembros de comunidad ===

def join_community(user, community_id):
    community = get_object_or_404(Community, id=community_id)

    if CommunityMember.objects.filter(user=user, community=community).exists():
        raise PermissionDenied("Ya eres miembro de esta comunidad.")

    # Busca o crea el rol "member"
    role, _ = CommunityRole.objects.get_or_create(name="member", defaults={"permissions": {}})
    
    CommunityMember.objects.create(
        user=user,
        community=community,
        role=role
    )
    return community


def list_community_members(community_id):
    return CommunityMember.objects.filter(community_id=community_id)


def create_community_member(user, data):
    role_id = data.pop('role_id')
    role = get_object_or_404(CommunityRole, id=role_id)
    data['role'] = role
    return CommunityMember.objects.create(**data)


def update_community_member(member_id, data):
    member = get_object_or_404(CommunityMember, id=member_id)
    role_id = data.pop('role_id', None)
    if role_id:
        member.role = get_object_or_404(CommunityRole, id=role_id)
    for field in ['user', 'community']:
        if field in data:
            setattr(member, field, data[field])
    member.save()
    return member
