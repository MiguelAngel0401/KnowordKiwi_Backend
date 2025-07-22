import factory
from faker import Faker
from users.factory import UserFactory
from communities.models import Community, CommunityRole, CommunityMember

fake = Faker()


class CommunityRoleFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = CommunityRole

    name = factory.LazyAttribute(lambda _: fake.unique.job())
    permissions = factory.LazyFunction(
        lambda: {
            "can_post": True,
            "can_edit": fake.boolean(chance_of_getting_true=50),
            "can_delete": fake.boolean(chance_of_getting_true=20),
            "can_invite": fake.boolean(chance_of_getting_true=80),
        }
    )


class CommunityFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Community

    name = factory.LazyAttribute(lambda _: fake.unique.company())
    description = factory.LazyAttribute(lambda _: fake.text(max_nb_chars=200))
    avatar_url = factory.LazyAttribute(lambda _: fake.image_url())
    banner_url = factory.LazyAttribute(lambda _: fake.image_url())
    is_private = factory.LazyAttribute(
        lambda _: fake.boolean(chance_of_getting_true=30)
    )
    created_by = factory.SubFactory(UserFactory)


class CommunityMemberFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = CommunityMember

    community = factory.SubFactory(CommunityFactory)
    user = factory.SubFactory(UserFactory)
    role = factory.SubFactory(CommunityRoleFactory)
