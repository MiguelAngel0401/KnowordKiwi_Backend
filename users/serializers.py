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
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ("email", "username", "real_name", "password")

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
        user = User.objects.create_user(**validated_data)

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
