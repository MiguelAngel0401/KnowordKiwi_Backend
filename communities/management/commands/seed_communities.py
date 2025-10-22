from django.core.management.base import BaseCommand
from communities.factory import (
    CommunityFactory,
    CommunityMemberFactory,
    CommunityRoleFactory,
)


class Command(BaseCommand):
    help = "Seed the database with test communities"

    def add_arguments(self, parser):
        parser.add_argument(
            "--total", type=int, default=5, help="Number of communities to create"
        )

    def handle(self, *args, **kwargs):
        total = kwargs["total"]
        self.stdout.write(f"Seeding {total} communities with members...")

        role_admin = CommunityRoleFactory(
            name="Admin", permissions={"can_invite": True, "can_delete": True}
        )
        role_member = CommunityRoleFactory(name="Member")

        for _ in range(total):
            community = CommunityFactory()
            # Añadir al creador como admin
            CommunityMemberFactory(
                community=community, user=community.created_by, role=role_admin
            )

            # Añadir otros miembros
            for _ in range(3):
                CommunityMemberFactory(community=community, role=role_member)

        self.stdout.write(f"Successfully seeded {total} communities.")
