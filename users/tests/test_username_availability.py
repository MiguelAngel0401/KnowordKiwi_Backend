from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

User = get_user_model()


class UsernameAvailabilityTests(APITestCase):
    """Pruebas para el endpoint de verificación de disponibilidad de username."""

    def setUp(self):
        """Configura un usuario para las pruebas que lo requieran."""
        self.existing_user = User.objects.create_user(
            email="existente@example.com",
            username="existente",
            password="password123",
            real_name="Usuario Existente",
        )
        self.url = reverse("check-username-availability")

    def test_username_is_available(self):
        """Verifica que el endpoint responda 'true' si el username no existe."""
        data = {"username": "nuevo_usuario"}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["available"])

    def test_username_is_not_available(self):
        """Verifica que el endpoint responda 'false' si el username ya existe."""
        data = {"username": "existente"}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["available"])

    def test_missing_username_payload(self):
        """Verifica que el endpoint responda 400 si no se envía el username."""
        response = self.client.post(self.url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)

    def test_authenticated_user_checks_own_username(self):
        """
        Verifica que un usuario autenticado pueda verificar su propio username
        y el resultado sea 'true' (disponible para él).
        """
        self.client.force_authenticate(user=self.existing_user)
        data = {"username": "existente"}
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["available"])

    def test_authenticated_user_checks_other_user_username(self):
        """
        Verifica que un usuario autenticado no pueda usar el username de otro usuario.
        """
        User.objects.create_user(
            email="otro@example.com",
            username="otro",
            password="password123",
            real_name="Otro Usuario",
        )
        self.client.force_authenticate(user=self.existing_user)
        data = {"username": "otro"}
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["available"])
