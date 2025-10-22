from django.contrib.auth import get_user_model
from django.urls import reverse
from django.core import mail
from rest_framework import status
from rest_framework.test import APITestCase

User = get_user_model()


class RegistrationTests(APITestCase):
    """Pruebas para el endpoint de registro de usuarios."""

    def setUp(self):
        """Configura los datos base para las pruebas de registro."""
        self.url = reverse("register")
        self.user_data = {
            "email": "nuevo.usuario@example.com",
            "username": "nuevousuario",
            "real_name": "Nuevo Usuario",
            "password": "passwordSeguro123",
        }

    def test_successful_registration(self):
        """
        Verifica que un usuario puede registrarse correctamente, se crea en la BD
        y se envía un correo de verificación.
        """
        self.assertEqual(len(mail.outbox), 0)  # No hay correos en la cola

        response = self.client.post(self.url, self.user_data)

        # 1. Verificar la respuesta de la API
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("Usuario registrado correctamente", response.data["message"])

        # 2. Verificar que el usuario se creó en la base de datos
        user = User.objects.get(email=self.user_data["email"])
        self.assertEqual(user.username, self.user_data["username"])
        self.assertTrue(user.check_password(self.user_data["password"]))
        self.assertFalse(user.is_email_verified)
        self.assertIsNotNone(user.email_verification_token)

        # 3. Verificar que se envió el correo de confirmación
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [self.user_data["email"]])
        self.assertEqual(mail.outbox[0].subject, "Confirma tu cuenta de KnoWord")

    def test_registration_fails_with_duplicate_email(self):
        """
        Verifica que el registro falla si el email ya está en uso.
        """
        # Crear un usuario con el mismo email que se intentará registrar
        User.objects.create_user(**self.user_data)

        response = self.client.post(self.url, self.user_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)
        self.assertEqual(
            response.data["email"][0], "Este correo electrónico ya está registrado."
        )
        self.assertEqual(User.objects.count(), 1)  # No se creó un nuevo usuario

    def test_registration_fails_with_duplicate_username(self):
        """
        Verifica que el registro falla si el username ya está en uso.
        """
        # Crear un usuario con el mismo username
        User.objects.create_user(
            email="diferente@example.com",
            username=self.user_data["username"],
            real_name="Otro Usuario",
            password="password123",
        )

        response = self.client.post(self.url, self.user_data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("username", response.data)
        self.assertEqual(
            response.data["username"][0], "Este nombre de usuario ya existe."
        )

    def test_registration_fails_with_short_password(self):
        """
        Verifica que el registro falla si la contraseña es menor a 8 caracteres.
        """
        data = self.user_data.copy()
        data["password"] = "1234"  # Contraseña corta

        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data)
        self.assertEqual(
            response.data["password"][0],
            "La contraseña debe tener un mínimo de 8 caracteres.",
        )
