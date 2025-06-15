import uuid
from datetime import timedelta
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


# Serializdor de Login
class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        if email and password:
            user = authenticate(
                request=self.context.get("request"), email=email, password=password
            )

            if not user:
                raise serializers.ValidationError(
                    "Credenciales inválidas, intenta de nuevo."
                )
            if not user.is_active:
                raise serializers.ValidationError("Esta cuenta está desactivada.")
        else:
            raise serializers.ValidationError("Se requiere correo y contraseña.")

        data["user"] = user
        return data


# Serializador de Registro


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializador para registrar nuevos usuarios.
    Campos:
        email (str): Dirección de correo electrónico del usuario. Debe ser único.
        username (str): Nombre de usuario elegido por el usuario. Debe ser único.
        real_name (str): Nombre real del usuario.
        password (str): Contraseña del usuario. Solo escritura, mínimo 8 caracteres.
        avatar_url (str, opcional): URL o referencia al avatar del usuario.
        bio (str, opcional): Biografía del usuario.
    Validaciones:
        - Asegura que el correo electrónico no esté ya registrado.
        - Asegura que el nombre de usuario no esté ya tomado.
    Creación:
        - Crea un nuevo usuario con los datos proporcionados.
        - Genera un token de verificación de correo electrónico y su marca de tiempo de expiración.
        - Envía un correo electrónico de confirmación al usuario con un enlace de verificación.
    Excepciones:
        serializers.ValidationError: Si el correo electrónico o el nombre de usuario ya existen.
    """

    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ("email", "username", "real_name", "password", "avatar_url", "bio")

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                "Este correo electrónico ya está registrado."
            )
        return value

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Este nombre de usuario ya existe.")
        return value

    def create(self, validated_data):
        email = validated_data.pop("email")
        username = validated_data.pop("username")
        real_name = validated_data.pop("real_name")
        password = validated_data.pop("password")

        # Crear el usuario con los datos proporcionados
        user = User.objects.create_user(
            email=email,
            username=username,
            real_name=real_name,
            password=password,
        )

        # Si se proporciona un avatar_url o una biografía, lo asignamos
        for attr, value in validated_data.items():
            setattr(user, attr, value)

        # Crear token y expiración
        user.email_verification_token = str(uuid.uuid4())
        user.email_verification_expires_at = timezone.now() + timedelta(hours=24)
        user.save()

        # Enviar correo
        subject = "Confirma tu cuenta de KnoWord"
        confirmation_link = f"http://localhost:3000/confirm-account?token={user.email_verification_token}/"

        html_message = render_to_string(
            "emails/confirmation_email.html",
            {"user": user, "confirmation_link": confirmation_link},
        )
        plain_message = strip_tags(html_message)

        try:
            send_mail(
                subject,
                plain_message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                html_message=html_message,
                fail_silently=False,
            )
            print("Correo enviado a", user.email)
        except Exception as e:
            print("Error al enviar el correo:", e)

        return user


# Serializador de Usuario
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = (
            "password",
            "email_verification_token",
            "email_verification_expires_at",
            "password_reset_token",
            "password_reset_expires_at",
        )
