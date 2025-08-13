import uuid
from django.db import models
from users.models import User


class SoftDeleteManager(models.Manager):
    """
    Manager personalizado para modelos con borrado lógico.
    Filtra automáticamente los objetos que tienen el campo 'deleted_at' establecido.
    """

    def get_queryset(self):
        return super().get_queryset().filter(deleted_at__isnull=True)


class SoftDeleteModel(models.Model):
    """Modelo abstracto para implementar el borrado lógico."""

    deleted_at = models.DateTimeField(blank=True, null=True)
    objects = SoftDeleteManager()  # Manager por defecto que filtra borrados.
    all_objects = models.Manager()  # Manager para acceder a todos los objetos.

    class Meta:
        abstract = True


class Community(SoftDeleteModel):
    """
    Modelo que representa una comunidad en la aplicacion.
    Cada comunidad tiene un nombre, descripcion, avatar, banner, y es privada o publica.
    Tambien tiene un campo para el usuario que la creo, y
    campos de fecha de creacion y actualizacion.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    avatar = models.URLField(blank=True, null=True)
    banner = models.URLField(blank=True, null=True)
    is_private = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="created_communities"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    tags = models.ManyToManyField("Tag", related_name="communities", blank=True)

    class Meta:
        """
        Clase Meta para configurar el modelo Community.
        """

        db_table = "communities"
        verbose_name = "Comunidad"
        verbose_name_plural = "Comunidades"

    def __str__(self):
        return str(self.name)


class CommunityRole(models.Model):
    """
    Modelo que representa un rol dentro de una comunidad.
    Cada rol tiene un nombre y permisos asociados.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50, unique=True)
    permissions = models.JSONField(default=dict)

    class Meta:
        """
        Clase Meta para configurar el modelo CommunityRole.
        """

        db_table = "community_roles"
        verbose_name = "Rol de Comunidad"
        verbose_name_plural = "Roles de Comunidades"

    def __str__(self):
        return str(self.name)


class CommunityMember(models.Model):
    """
    Modelo que representa un miembro de una comunidad.
    Cada miembro tiene un rol, una comunidad asociada y un usuario.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    community = models.ForeignKey(
        Community, on_delete=models.CASCADE, related_name="memberships"
    )
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="community_memberships"
    )
    role = models.ForeignKey(
        CommunityRole, on_delete=models.CASCADE, related_name="members"
    )
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        """
        Clase Meta para configurar el modelo CommunityMember.
        Esta clase define la tabla, las restricciones de unicidad y los indices.
        """

        db_table = "community_members"
        unique_together = ("community", "user")
        indexes = [
            models.Index(fields=["community", "user"]),
        ]
        verbose_name = "Miembro de la comunidad"
        verbose_name_plural = "Miembros de comunidades"

    def __str__(self):
        return f"{self.user.name} - {self.community.name} ({self.role.name})"


class Tag(models.Model):
    """
    Representa una etiqueta (categoría temática) que puede asociarse a una o varias comunidades.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        """
        Clase Meta para configurar el modelo Tag.
        """

        db_table = "tags"
        verbose_name = "Etiqueta"
        verbose_name_plural = "Etiquetas"

    def __str__(self):
        return str(self.name)
