import uuid
from django.db import models
from django.core.exceptions import ValidationError
from users.models import User


class UserRelationship(models.Model):
    """
    Representa una relación de seguimiento entre dos usuarios.

    Esta clase se utiliza para gestionar quién sigue a quién, sirviendo como la
    tabla de unión para una relación de muchos a muchos entre usuarios.
    Incluye validaciones a nivel de base de datos y de aplicación para
    asegurar la integridad de los datos.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    follower = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="following",
        verbose_name="Usuario Seguidor",
        help_text="Usuario que sigue a otro.",
    )
    # Usuario que sigue a otro

    following = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="followers",
        verbose_name="Usuario Seguido",
        help_text="Usuario que está siendo seguido.",
    )
    # Usuario que está siendo seguido

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Fecha de Creación",
        help_text="Fecha y hora en que se creó la relación.",
    )

    class Meta:
        """Configuración del modelo a nivel de base de datos y Django."""

        db_table = '"users"."user_follows"'
        unique_together = ("follower", "following")
        indexes = [
            models.Index(fields=["follower"]),
            models.Index(fields=["following"]),
        ]
        constraints = [
            models.CheckConstraint(
                check=~models.Q(follower=models.F("following")),
                name="prevent_self_follow",
            )
        ]
        verbose_name = "Seguimiento de Usuario"
        verbose_name_plural = "Seguimientos de Usuarios"

    def clean(self):
        """Valida a nivel de aplicación que un usuario no puede seguirse a sí mismo."""
        if self.follower == self.following:
            raise ValidationError("Un usuario no puede seguirse a sí mismo.")

    def save(self, *args, **kwargs):
        """Llama al método 'clean' antes de guardar el objeto."""
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        """Representación en cadena para el panel de administración."""
        return f"{self.follower.username} sigue a {self.following.username}"


class UserFollow(UserRelationship):
    """
    Modelo proxy para UserRelationship.

    Proporciona un alias para el modelo UserRelationship, útil para
    personalizar el comportamiento o la visualización en el admin sin
    crear una nueva tabla en la base de datos.
    """

    class Meta:
        """Configuración para el modelo proxy."""

        proxy = True
        verbose_name = "Alias de Seguimiento"
        verbose_name_plural = "Alias de Seguimientos"
