from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserLoginSerializer, UserRegistrationSerializer, UserSerializer
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

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
                max_age=timezone.timedelta(days=14).total_seconds(),
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
        """
        Verifica si un correo electrónico ya está registrado.
        """
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
        """Verifica si un nombre de usuario ya está registrado."""

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


class LogoutView(APIView):
    """
    Vista para cerrar la sesión de un usuario.
    Elimina la cookie de refresco para cerrar la sesión.
    """

    def post(self, request):
        """
        Cierra la sesión del usuario eliminando la cookie de refresco.
        """
        response = Response(
            {"message": "Logout exitoso."},
            status=status.HTTP_200_OK,
        )
        response.delete_cookie("refresh_token")
        return response
    

class UserProfileView(RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        
        if serializer.is_valid():
            serializer.save()
            return Response({
                'user': serializer.data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#drf django_spectacular