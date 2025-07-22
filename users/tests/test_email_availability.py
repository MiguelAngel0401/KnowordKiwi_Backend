from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

User = get_user_model()


class EmailAvailabilityTests(APITestCase):
    """Pruebas para el endpoint de verificación de disponibilidad de correo."""

    def setUp(self):
        """Configura un usuario para las pruebas que lo requieran."""
        self.existing_user = User.objects.create_user(
            email="existente@example.com",
            username="existente",
            password="password123",
            real_name="Usuario Existente",
        )
        self.url = reverse("check-email-availability")

    def test_email_is_available(self):
        """Verifica que el endpoint responda 'true' si el email no existe."""
        data = {"email": "nuevo.usuario@example.com"}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["available"])

    def test_email_is_not_available(self):
        """Verifica que el endpoint responda 'false' si el email ya existe."""
        data = {"email": "existente@example.com"}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["available"])

    def test_missing_email_payload(self):
        """Verifica que el endpoint responda 400 si no se envía el email."""
        response = self.client.post(self.url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", response.data)

    def test_authenticated_user_checks_own_email(self):
        """
        Verifica que un usuario autenticado pueda verificar su propio email
        y el resultado sea 'true' (disponible para él).
        """
        self.client.force_authenticate(user=self.existing_user)
        data = {"email": "existente@example.com"}
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["available"])

    def test_authenticated_user_checks_other_user_email(self):
        """
        Verifica que un usuario autenticado no pueda usar el email de otro usuario.
        """
        User.objects.create_user(
            email="otro@example.com",
            username="otro",
            password="password123",
            real_name="Otro Usuario",
        )
        self.client.force_authenticate(user=self.existing_user)
        data = {"email": "otro@example.com"}
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["available"])
