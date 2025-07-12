from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

User = get_user_model()


class LoginLogoutTest(APITestCase):
    """Pruebas para el endpoint de inicio de sesión y cierre de sesión."""

    def setUp(self):
        """Configura un usuario para las pruebas que lo requieran."""
        self.password = "passwordSeguro123"
        self.verified_user = User.objects.create_user(
            email="verificado@example.com",
            username="verificado",
            real_name="Usuario Verificado",
            password=self.password,
        )
        self.verified_user.is_email_verified = True
        self.verified_user.save()

        self.unverified_user = User.objects.create_user(
            email="noVerificado@example.com",
            username="noVerificado",
            real_name="Usuario No Verificado",
            password=self.password,
        )

        self.login_url = reverse("login")
        self.logout_url = reverse("logout")

    def test_successful_login_with_verified_user(self):
        """Verifica que un usuario con email verificado pueda iniciar sesion
        y recibe las cookies de sesion
        """
        data = {"email": self.verified_user.email, "password": self.password}
        response = self.client.post(self.login_url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("user", response.data)
        self.assertEqual(response.data["user"]["email"], self.verified_user.email)
        self.assertIn("access_token", response.cookies)
        self.assertIn("refresh_token", response.cookies)

    def test_login_fails_for_unverified_user(self):
        """Verifica que un usuario con email no verificado no pueda iniciar sesion."""
        data = {"email": self.unverified_user.email, "password": self.password}
        response = self.client.post(self.login_url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data["error"],
            "Por favor verifica tu correo antes de iniciar sesión.",
        )
        self.assertNotIn("access_token", response.cookies)

    def test_login_fails_with_invalid_credentials(self):
        """Verifica que el login falla con una contraseña incorrecta."""
        data = {"email": self.verified_user.email, "password": "wrongpassword"}
        response = self.client.post(self.login_url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Credenciales inválidas", str(response.data))

    def test_successful_logout(self):
        """
        Verifica que el logout elimina las cookies de sesión.
        """
        # Primero, iniciamos sesión para obtener las cookies
        login_data = {"email": self.verified_user.email, "password": self.password}
        self.client.post(self.login_url, login_data)

        # Ahora, cerramos sesión
        response = self.client.post(self.logout_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.cookies["access_token"]["max-age"], 0)
        self.assertEqual(response.cookies["refresh_token"]["max-age"], 0)
