from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.views import APIView
from django.core.validators import validate_email
from rest_framework.response import Response
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserLoginSerializer, UserRegistrationSerializer

User = get_user_model()


class RegisterView(APIView):
    """
    Vista de API para el registro de nuevos usuarios.

    Maneja solicitudes POST para registrar nuevos usuarios. Valida los datos proporcionados
    usando el serializador `UserRegistrationSerializer`. Si los datos son válidos,
    crea un nuevo usuario y devuelve un mensaje de éxito indicando al usuario que
    verifique su correo electrónico para completar el proceso de registro.
    Si los datos no son válidos, devuelve un error con los detalles de la validación
    y un estado HTTP 400 (Bad Request).

    Metodos:
        post(request): Maneja el registro de usuario a través de una solicitud POST.
    """

    def post(self, request):
        """Maneja el registro de usuario a través de una solicitud POST."""

        serializer = UserRegistrationSerializer(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "message": "Usuario registrado correctamente. "
                    "Revisa tu correo para verificar tu cuenta."
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """
    Vista de API para el inicio de sesión de usuarios.

    Maneja solicitudes POST para iniciar sesión de usuarios. Valida los datos proporcionados
    usando el serializador `UserLoginSerializer`. Si los datos son válidos,
    devuelve un token de acceso y un token de actualización para el usuario.
    Si los datos no son válidos, devuelve un error con los detalles de
    la validación y un estado HTTP 400 (Bad Request).
    Metodos:
        post(request): Maneja el inicio de sesión de usuario a través de una solicitud POST.
    """

    def post(self, request):
        """Maneja el inicio de sesión de usuario a través de una solicitud POST."""
        serializer = UserLoginSerializer(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid():
            user = serializer.validated_data["user"]

            refresh = RefreshToken.for_user(user)
            return Response(
                {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                },
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    """
    Vista para verificar el correo electrónico del usuario

    Maneja solicitudes GET para verificar el correo electrónico del usuario.
    Busca al usuario por el token de verificación proporcionado en la URL.
    Si el usuario no existe o el token de verificación ha expirado,
    devuelve un error con un mensaje de error y un estado HTTP 400 (Bad Request).
    Si el usuario es encontrado y el token de verificación es válido,
    actualiza la propiedad `is_email_verified` del usuario y lo guarda.
    Devuelve un mensaje de éxito indicando que el correo fue verificado correctamente.

    Metodos:
        get(request, token): Maneja la verificación de correo electrónico
        a través de una solicitud GET.
    """

    def get(self, request, token):
        """Maneja la verificación de correo electrónico a través de una solicitud GET."""

        try:
            user = User.objects.get(email_verification_token=token)

            if (
                user.email_verification_expires_at
                and user.email_verification_expires_at < timezone.now()
            ):
                return Response(
                    {"error": "El token de verificación ha expirado."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user.is_email_verified = True
            user.email_verification_token = None
            user.email_verification_expires_at = None
            user.save()

            return Response(
                {"message": "Correo verificado correctamente."},
                status=status.HTTP_200_OK,
            )

        except User.DoesNotExist:
            return Response(
                {"error": "Token inválido o usuario no encontrado."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class CheckEmailAvailabilityView(APIView):
    """
    Vista para verificar si un correo electrónico es válido y está disponible
    Maneja solicitudes POST para verificar la disponibilidad de un correo electrónico.
    Si el correo electrónico es válido y no está registrado, devuelve un mensaje de
    disponibilidad con un estado HTTP 200 (OK) (Valido para que funcione la validacion frontend).
    Si el correo electrónico no es válido, devuelve un error con un mensaje de error
    y un estado HTTP 200 (OK) (Valido para que funcione la validacion frontend).
    Si el correo electrónico ya esta registrado, devuelve un mensaje de disponibilidad
    con un estado HTTP 200 (OK).
    Metodos:
        post(request): Maneja la verificación de disponibilidad del correo electrónico
    """

    def post(self, request):
        """Maneja la verificación de disponibilidad del correo electrónico a
        través de una solicitud POST."""

        email = request.data.get("email")
        if not email:
            return Response(
                {"error": "El campo 'email' es obligatorio."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            validate_email(email)
        except DjangoValidationError:
            return Response(
                {"error": "El correo electrónico no es válido."},
                status=status.HTTP_200_OK,
            )
        if User.objects.filter(email=email).exists():
            return Response(
                {
                    "available": False,
                    "message": "Este correo electrónico ya está registrado.",
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"available": True, "message": "Correo electrónico disponible."},
                status=status.HTTP_200_OK,
            )


class CheckUsernameAvailabilityView(APIView):
    """
    Vista para verificar la disponibilidad del nombre de usuario
    Maneja solicitudes POST para verificar la disponibilidad del nombre de usuario.
    Si el nombre de usuario ya está en uso, devuelve un mensaje de no disponibilidad
    con un estado HTTP 200 (OK).
    Si el nombre de usuario no esta registrado, devuelve un mensaje de disponibilidad
    con un estado HTTP 200 (OK).
    Metodos:
        post(request): Maneja la verificación de disponibilidad del nombre de usuario
    """

    def post(self, request):
        """Maneja la verificación de disponibilidad del nombre de usuario a
        través de una solicitud POST."""

        username = request.data.get("username")
        if not username:
            return Response(
                {"error": "El campo 'username' es obligatorio."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        exists = User.objects.filter(username=username).exists()
        if exists:
            return Response(
                {
                    "available": False,
                    "message": "El nombre de usuario ya está en uso.",
                },
                status=status.HTTP_200_OK,
            )
        return Response(
            {
                "available": True,
                "message": "El nombre de usuario está disponible.",
            },
            status=status.HTTP_200_OK,
        )
