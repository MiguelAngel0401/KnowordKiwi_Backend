from django.contrib.auth import get_user_model
from django.forms import ValidationError
from django.utils import timezone
from django.conf import settings
from django.core.validators import validate_email
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from .authentication import CookieJWTAuthentication
from .serializers import (
    UserLoginSerializer,
    UserRegistrationSerializer,
    UserSerializer,
    UserUpdateSerializer,
)


User = get_user_model()


class RegisterView(APIView):
    """
    Vista para registrar nuevos usuarios.
    Esta vista recibe los datos del usuario, valida la información,
    crea el usuario y envía un correo electrónico de verificación.
    Metodos:
        post: Registra un nuevo usuario.
        Requiere los campos 'email', 'username', 'real_name', 'password',
        'avatar_url' y 'bio' (opcionales) en el cuerpo de la solicitud.
    """

    def post(self, request):
        """
        Registra un nuevo usuario.
        """
        serializer = UserRegistrationSerializer(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "message": "Usuario registrado correctamente. Revisa tu correo para verificar tu cuenta."
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """
    Vista para iniciar sesión de usuarios.
    Esta vista recibe los datos de inicio de sesión, valida la información,
    y devuelve un token de acceso y un token de actualización.
    Metodos:
        post: Inicia sesión de un usuario.
        Requiere los campos 'email' y 'password' en el cuerpo de la solicitud.
    """

    def post(self, request):
        """
        Inicia sesión de un usuario.
        """
        serializer = UserLoginSerializer(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid():
            user = serializer.validated_data["user"]

            # Opcional: evitar login si no ha verificado su correo
            if not user.is_email_verified:
                return Response(
                    {"error": "Por favor verifica tu correo antes de iniciar sesión."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            user_data = UserSerializer(user).data

            refresh = RefreshToken.for_user(user)

            response = Response(
                {"user": user_data},
                status=status.HTTP_200_OK,
            )

            # Configurar la cookie del token de acceso
            response.set_cookie(
                key="access_token",
                value=str(refresh.access_token),
                httponly=True,
                secure=not settings.DEBUG,  # True en producción
                samesite="Lax",
                max_age=settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds(),
            )

            # Configurar la cookie del token de refresco
            response.set_cookie(
                key="refresh_token",
                value=str(refresh),
                httponly=True,
                secure=not settings.DEBUG,  # True en producción
                samesite="Lax",  # Cambiar a 'Strict' si es necesario
                max_age=settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds(),
            )
            return response

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    """
    Vista para verificar el correo electrónico del usuario
    Esta vista recibe un token de verificación y actualiza el estado del usuario
    para indicar que su correo ha sido verificado.
    El token debe ser único y tener una fecha de expiración.
    Metodos:
        get: Verifica el correo electrónico del usuario utilizando un token.
        Este token debe ser enviado como parte de la URL.
    """

    def get(self, request, token):  # pylint: disable=unused-argument
        """
        Verifica el correo electrónico del usuario utilizando un token.
        """
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
    Vista para verificar la disponibilidad del correo electrónico.
    Si el usuario está autenticado, excluye su propio correo de la verificación,
    permitiendo su reutilización en la página de edición de perfil.
    """

    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Verifica si un correo electrónico ya está registrado por OTRO usuario.
        """
        email = request.data.get("email")
        if not email:
            return Response(
                {"error": "El campo 'email' es obligatorio."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # validar que el correo electronico tenga el formato correcto
        try:
            validate_email(email)
        except ValidationError:
            return Response(
                {"error": "El correo electronico no tiene el formato correcto."},
                status=status.HTTP_200_OK,
            )

        # Usamos iexact para una comparación insensible a mayúsculas/minúsculas
        queryset = User.objects.filter(email__iexact=email)

        # Si el usuario está autenticado, excluimos su propio registro de la búsqueda
        if request.user and request.user.is_authenticated:
            queryset = queryset.exclude(pk=request.user.pk)

        exists = queryset.exists()
        return Response(
            {"available": not exists},
            status=status.HTTP_200_OK,
        )


class CheckUsernameAvailabilityView(APIView):
    """
    Vista para verificar la disponibilidad del nombre de usuario.
    Si el usuario está autenticado, excluye su propio username de la verificación,
    permitiendo su reutilización en la página de edición de perfil.
    """

    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [AllowAny]

    def post(self, request):
        """Verifica si un nombre de usuario ya está registrado por OTRO usuario."""

        username = request.data.get("username")
        if not username:
            return Response(
                {"error": "El campo 'username' es obligatorio."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verificar que el username tiene al menos tres caracteres
        if len(username) < 3:
            return Response(
                {"error": "Tu nombre de usuario debe tener al menos 3 caracteres."},
                status=status.HTTP_200_OK,
            )

        # Usamos iexact para una comparación insensible a mayúsculas/minúsculas
        queryset = User.objects.filter(username__iexact=username)

        # Si el usuario está autenticado, excluimos su propio registro de la búsqueda
        if request.user and request.user.is_authenticated:
            queryset = queryset.exclude(pk=request.user.pk)

        exists = queryset.exists()
        return Response(
            {"available": not exists},
            status=status.HTTP_200_OK,
        )


class CookieTokenRefreshView(TokenRefreshView):
    """
    Vista para refrescar el token de acceso utilizando un
    token de actualización almacenado en cookies.
    Esta vista asume que el token de actualización se
    almacena en una cookie llamada "refresh_token".
    """

    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get("refresh_token")

        if refresh_token is None:
            return Response(
                {"error": "No se encontró el token de actualización en las cookies."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        serializer = self.get_serializer(data={"refresh": refresh_token})

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0]) from e

        response = Response(
            {"message": "Token de acceso refrescado correctamente."},
            status=status.HTTP_200_OK,
        )

        # Configurar la nueva cookie del token de acceso
        response.set_cookie(
            key="access_token",
            value=serializer.validated_data["access"],
            httponly=True,
            secure=not settings.DEBUG,  # True en producción
            samesite="Lax",
            max_age=settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds(),
        )

        return response


class LogoutView(APIView):
    """
    Vista para cerrar la sesión de un usuario.
    Elimina la cookie de refresco para cerrar la sesión.
    """

    def post(self, request):  # pylint: disable=unused-argument
        """
        Cierra la sesión del usuario eliminando la cookie de refresco.
        """
        response = Response(
            {"message": "Logout exitoso."},
            status=status.HTTP_200_OK,
        )
        response.delete_cookie("refresh_token")
        response.delete_cookie("access_token")
        return response


class UserProfileView(generics.RetrieveUpdateAPIView):
    """
    Vista para que los usuarios vean y actualicen su perfil.
    Permite peticiones GET para obtener los datos y PATCH para actualizarlos.
    """

    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = User.objects.all()
    serializer_class = UserUpdateSerializer

    def get_object(self):
        """
        Sobrescribimos este método para asegurar que el usuario
        solo pueda acceder a su propio perfil.
        """
        return self.request.user


# drf django_spectacular
