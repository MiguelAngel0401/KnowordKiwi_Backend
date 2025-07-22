from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken


class CookieJWTAuthentication(JWTAuthentication):
    """
    Clase de autenticación personalizada que extrae el JWT de una cookie HttpOnly
    llamada 'access_token' en lugar de la cabecera 'Authorization'.
    """

    def authenticate(self, request):
        # Obtiene el token de la cookie 'access_token'
        raw_token = request.COOKIES.get("access_token")
        if raw_token is None:
            return None

        try:
            # Valida el token usando la lógica de la clase base
            validated_token = self.get_validated_token(raw_token)
            return self.get_user(validated_token), validated_token
        except InvalidToken:
            return None
