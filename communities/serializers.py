from rest_framework import serializers
from users.models import User
from .models import Community, CommunityMember, CommunityRole, Tag


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ["id", "name"]


class CommunitySerializer(serializers.ModelSerializer):
    read_tags = TagSerializer(source="tags", many=True, read_only=True)
    tags = serializers.ListField(
        child=serializers.CharField(),
        write_only=True,
    )

    class Meta:
        model = Community
        fields = "__all__"
        read_only_fields = (
            "id",
            "created_by",
            "created_at",
            "updated_at",
            "deleted_at",
        )

    def create(self, validated_data):
        tags = validated_data.pop("tags", [])
        community = Community.objects.create(**validated_data)

        for name in tags:
            tag, _ = Tag.objects.get_or_create(
                name__iexact=name.strip(), defaults={"name": name.strip()}
            )
            community.tags.add(tag)

        return community

    def update(self, instance, validated_data):
        tags = validated_data.pop("tags", [])

        # Actualizar campos normales
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Limpiar y reasignar tags
        instance.tags.clear()
        for name in tags:
            tag, _ = Tag.objects.get_or_create(
                name__iexact=name.strip(), defaults={"name": name.strip()}
            )
            instance.tags.add(tag)

        return instance


class CommunityRoleSerializer(
    serializers.ModelSerializer
):  # Serilizers para los admins
    class Meta:
        model = CommunityRole
        fields = "__all__"
        read_only_fields = ("id",)


class CommunityMemberSerializer(
    serializers.ModelSerializer
):  # Eso de aca sirve para saber que tipo de usuario son
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    role = CommunityRoleSerializer(read_only=True)
    role_id = serializers.UUIDField(write_only=True)

    class Meta:
        model = CommunityMember
        fields = ["id", "user", "community", "role", "role_id", "joined_at"]
        read_only_fields = ("id", "joined_at")

    def create(self, validated_data):
        role_id = validated_data.pop("role_id")
        role = CommunityRole.objects.get(id=role_id)
        validated_data["role"] = role
        return super().create(validated_data)

    def update(self, instance, validated_data):
        role_id = validated_data.pop("role_id", None)
        if role_id:
            instance.role = CommunityRole.objects.get(id=role_id)
        return super().update(instance, validated_data)


class JoinCommunitySerializer(
    serializers.Serializer
):  # Esto de aca es para unirse a las comunidades
    community_id = serializers.UUIDField()

    def validate_community_id(self, value):
        from .models import Community


# TagSerializer is now defined above CommunitySerializer


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ["id", "name"]
