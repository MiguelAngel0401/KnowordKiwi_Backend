from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserLoginSerializer, UserRegistrationSerializer

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

            refresh = RefreshToken.for_user(user)
            return Response(
                {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                },
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Vista de verificación de correo
class VerifyEmailView(APIView):
    def get(self, request, token):
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
