from django.core.management.base import BaseCommand
from users.factory import UserFactory


class Command(BaseCommand):
    help = "Seed the database with test users"

    def add_arguments(self, parser):
        parser.add_argument(
            "--total", type=int, default=5, help="Number of users to create"
        )

    def handle(self, *args, **kwargs):
        total = kwargs["total"]
        self.stdout.write(f"Seeding {total} users...")
        for _ in range(total):
            UserFactory()
        self.stdout.write(f"Successfully created {total} users.")
