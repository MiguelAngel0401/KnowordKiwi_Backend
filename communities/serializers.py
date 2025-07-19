from rest_framework import serializers
from .models import Community, CommunityMember, CommunityRole
from users.models import User  # Asegúrate de importar tu modelo User

class CommunitySerializer(serializers.ModelSerializer):
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    members_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Community
        fields = '__all__'
        read_only_fields = ('id', 'created_by', 'created_at', 'updated_at', 'deleted_at')
    
    def get_members_count(self, obj):
        return obj.memberships.count()


class CommunityRoleSerializer(serializers.ModelSerializer): #Serilizers para los admins
    class Meta:
        model = CommunityRole
        fields = '__all__'
        read_only_fields = ('id',)


class CommunityMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommunityMember
        fields = '__all__'


class JoinCommunitySerializer(serializers.Serializer): #Esto de aca es para unirse a las comunidades
    community_id = serializers.UUIDField()

    def validate_community_id(self, value):
        from .models import Community
        if not Community.objects.filter(id=value).exists():
            raise serializers.ValidationError("La comunidad no existe.")
        return value
