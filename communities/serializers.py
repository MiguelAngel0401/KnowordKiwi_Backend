from rest_framework import serializers
from users.models import User
from .models import Community, CommunityMember, CommunityRole, Tag


class TagSerializer(serializers.ModelSerializer):
    """
    Serializer para el modelo Tag.
    Utilizado para representar las etiquetas asociadas a las comunidades.
    """

    class Meta:
        """
        Clase Meta para configurar el serializer TagSerializer.
        """

        model = Tag
        fields = ["id", "name"]


class CommunitySerializer(serializers.ModelSerializer):
    """
    Serializador para el modelo Community, que maneja la serialización y
    deserialización de instancias de comunidad,
    incluyendo la gestión de etiquetas.

    Campos:
    - read_tags (TagSerializer): Representación de solo lectura
      de las etiquetas relacionadas.
    - tags (ListField): Lista de solo escritura de nombres de
      etiquetas para creación y actualización.

    Meta:
    model: Community
    fields: Todos los campos del modelo.
    read_only_fields: id, created_by, created_at, updated_at, deleted_at
    Métodos:

    - create(validated_data): Crea una instancia de Community y asocia etiquetas por nombre,
    creando nuevas etiquetas si es necesario.
    - update(instance, validated_data): Actualiza una instancia de Community
    y reasigna etiquetas por nombre,
    creando nuevas etiquetas si es necesario.
    """

    read_tags = TagSerializer(source="tags", many=True, read_only=True)
    tags = serializers.ListField(
        child=serializers.CharField(),
        write_only=True,
    )
    member_count = serializers.IntegerField(read_only=True)
    is_member = serializers.SerializerMethodField()
    is_owner = serializers.SerializerMethodField()
    can_edit = serializers.SerializerMethodField()

    class Meta:
        """
        Clase Meta para configurar el serializer CommunitySerializer.
        """

        model = Community
        fields = [
            "id",
            "name",
            "description",
            "avatar",
            "banner",
            "is_private",
            "created_by",
            "created_at",
            "updated_at",
            "deleted_at",
            "tags",
            "read_tags",
            "member_count",
            "is_member",
            "is_owner",
            "can_edit",
        ]
        read_only_fields = (
            "id",
            "created_by",
            "created_at",
            "updated_at",
            "deleted_at",
        )

    def get_is_member(self, obj):
        """Comprueba si el usuario que realiza la solicitud es miembro de la comunidad."""
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return False
        return CommunityMember.objects.filter(community=obj, user=request.user).exists()

    def get_is_owner(self, obj):
        """Comprueba si el usuario que realiza la solicitud es el creador de la comunidad."""
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return False
        return obj.created_by == request.user

    def get_can_edit(self, obj):
        """
        Comprueba si el usuario que realiza la solicitud puede editar la comunidad.
        Un usuario puede editar si es el propietario o si su rol de miembro
        tiene el permiso 'can_edit'.
        """
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return False

        # El propietario siempre puede editar.
        if obj.created_by == request.user:
            return True

        # Comprobar si es un miembro con permisos de edición.
        member = (
            CommunityMember.objects.filter(community=obj, user=request.user)
            .select_related("role")
            .first()
        )
        if member:
            return member.role.permissions.get("can_edit", False)

        return False

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
        tags_data = validated_data.pop("tags", None)

        # Actualizar campos normales
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Limpiar y reasignar tags solo si se proporcionan en la solicitud
        if tags_data is not None:
            instance.tags.clear()
            for name in tags_data:
                tag, _ = Tag.objects.get_or_create(
                    name__iexact=name.strip(), defaults={"name": name.strip()}
                )
                instance.tags.add(tag)

        return instance


class CommunityRoleSerializer(serializers.ModelSerializer):
    """
    Serializador para el modelo CommunityRole.

    Este serializer se encarga de la serialización y deserialización de los roles
    dentro de una comunidad, permitiendo representar y validar los datos asociados
    a los distintos roles que pueden tener los miembros de una comunidad.

    Meta:
        model: CommunityRole
        fields: Todos los campos del modelo.
        read_only_fields: id (el identificador es de solo lectura).
    """

    class Meta:
        """
        Clase Meta para configurar el serializer CommunityRoleSerializer.
        """

        model = CommunityRole
        fields = "__all__"
        read_only_fields = ("id",)


class CommunityMemberSerializer(serializers.ModelSerializer):
    """
    Serializador para el modelo CommunityMember.

    Este serializer gestiona la serialización y deserialización de los miembros de una comunidad,
    permitiendo representar y validar los datos asociados a la relación entre usuarios y comunidades,
    incluyendo el rol que desempeñan dentro de la comunidad.

    Campos:
    - user: Referencia al usuario miembro de la comunidad (solo escritura).
    - role: Representación del rol asignado al miembro (solo lectura).
    - role_id: Identificador del rol a asignar (solo escritura).
    - community: Comunidad a la que pertenece el miembro.
    - joined_at: Fecha de ingreso del miembro a la comunidad (solo lectura).

    Métodos:
    - create(validated_data): Crea una instancia de CommunityMember
    asignando el rol correspondiente.
    - update(instance, validated_data): Actualiza la instancia de CommunityMember
      y su rol si es necesario.

    Meta:
        model: CommunityMember
        fields: id, user, community, role, role_id, joined_at
        read_only_fields: id, joined_at
    """

    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    role = CommunityRoleSerializer(read_only=True)
    role_id = serializers.UUIDField(write_only=True)

    class Meta:
        """
        Clase Meta para configurar el serializer CommunityMemberSerializer.
        """

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
