import uuid
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)


class CustomUserManager(BaseUserManager):
    """
    Gestiona la creación y administración de instancias del modelo de usuario.

    Ofrece métodos para:
    - Crear usuarios estándar con correo electrónico y nombre de usuario.
    - Crear superusuarios con permisos administrativos.
    """

    def create_user(self, email, username, real_name, password=None, **extra_fields):
        """
        Crea y guarda un usuario con un conjunto mínimo de datos.

        Args:
            email (str): El email, que actúa como identificador único.
            username (str): El nombre de usuario.
            real_name (str): El nombre real del usuario.
            password (str, opcional): La contraseña del usuario.

        Raises:
            ValueError: Si el email no es proporcionado.

        Returns:
            User: La instancia del usuario recién creado.
        """
        if not email:
            raise ValueError(
                "El email es un campo obligatorio para la creación de usuarios."
            )

        email = self.normalize_email(email)
        user = self.model(
            email=email, username=username, real_name=real_name, **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, real_name, password, **extra_fields):
        """
        Crea y guarda un superusuario con todos los permisos administrativos.

        Args:
            email (str): El email, que actúa como identificador único.
            username (str): El nombre de usuario.
            real_name (str): El nombre real del usuario.
            password (str): La contraseña del superusuario.

        Returns:
            User: La instancia del superusuario recién creado.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        user = self.create_user(email, username, real_name, password, **extra_fields)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    """
    Modelo de usuario personalizado que extiende el sistema de autenticación de Django.

    Diseñado para una arquitectura de red social.
    Utiliza el email como campo de autenticación principal.
    Incluye campos de perfil, validación y control de estado de cuenta.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, max_length=255)
    username = models.CharField(max_length=50, unique=True)
    real_name = models.CharField(max_length=100)
    avatar = models.URLField(max_length=500, blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=255, blank=True, null=True)
    email_verification_expires_at = models.DateTimeField(blank=True, null=True)
    password_reset_token = models.CharField(max_length=255, blank=True, null=True)
    password_reset_expires_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username", "real_name"]

    class Meta:
        """
        Configuración de metadatos del modelo.

        db_table (str): Define la tabla de la base de datos, incluyendo el schema.
        verbose_name (str): Nombre legible del modelo en singular.
        verbose_name_plural (str): Nombre legible del modelo en plural.
        """

        db_table = '"users"."users"'
        verbose_name = "Usuario"
        verbose_name_plural = "Usuarios"

    def __str__(self):
        """
        Representación en cadena del objeto Usuario.

        Muestra el email del usuario para una fácil identificación.
        """
        return str(self.email) if self.email is not None else ""
