from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserLoginSerializer, UserRegistrationSerializer, UserSerializer
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

User = get_user_model()


# Vista de registro
class RegisterView(APIView):
    def post(self, request):
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


# Vista de login
class LoginView(APIView):
    def post(self, request):
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
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            response = Response(
                {"access": access_token, "user": user_data},
                status=status.HTTP_200_OK,
            )

            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=False,  # Cambiar a True en producción
                samesite="Lax",  # Cambiar a 'Strict' si es necesario
                max_age=timezone.timedelta(days=30).total_seconds(),
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

    def get(self, request, token):
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
    """Vista para verificar la disponibilidad del correo electrónico"""

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response(
                {"error": "El campo 'email' es obligatorio."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        exists = User.objects.filter(email=email).exists()
        return Response(
            {"available": not exists},
            status=status.HTTP_200_OK,
        )


class CheckUsernameAvailabilityView(APIView):
    """Vista para verificar la disponibilidad del nombre de usuario"""

    def post(self, request):
        username = request.data.get("username")
        if not username:
            return Response(
                {"error": "El campo 'username' es obligatorio."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        exists = User.objects.filter(username=username).exists()
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

        return Response(serializer.validated_data, status=status.HTTP_200_OK)
