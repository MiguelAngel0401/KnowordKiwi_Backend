from rest_framework import serializers
from .models import Community, CommunityMember, CommunityRole
from users.models import User  # Asegúrate de importar tu modelo User

class CommunitySerializer(serializers.ModelSerializer): #Esto sirve como serializers en comunidades
    class Meta:
        model = Community
        fields = '__all__'
        read_only_fields = ('id', 'created_by', 'created_at', 'updated_at', 'deleted_at')


class CommunityRoleSerializer(serializers.ModelSerializer): #Serilizers para los admins
    class Meta:
        model = CommunityRole
        fields = '__all__'
        read_only_fields = ('id',)


class CommunityMemberSerializer(serializers.ModelSerializer): #Eso de aca sirve para saber que tipo de usuario son
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    role = CommunityRoleSerializer(read_only=True)
    role_id = serializers.UUIDField(write_only=True)

    class Meta:
        model = CommunityMember
        fields = ['id', 'user', 'community', 'role', 'role_id', 'joined_at']
        read_only_fields = ('id', 'joined_at')

    def create(self, validated_data):
        role_id = validated_data.pop('role_id')
        role = CommunityRole.objects.get(id=role_id)
        validated_data['role'] = role
        return super().create(validated_data)

    def update(self, instance, validated_data):
        role_id = validated_data.pop('role_id', None)
        if role_id:
            instance.role = CommunityRole.objects.get(id=role_id)
        return super().update(instance, validated_data)


class JoinCommunitySerializer(serializers.Serializer): #Esto de aca es para unirse a las comunidades
    community_id = serializers.UUIDField()

    def validate_community_id(self, value):
        from .models import Community
        if not Community.objects.filter(id=value).exists():
            raise serializers.ValidationError("La comunidad no existe.")
        return value
