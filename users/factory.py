import factory
from faker import Faker
from users.models import User

fake = Faker()


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = User

    email = factory.LazyAttribute(lambda _: fake.unique.email())
    username = factory.LazyAttribute(lambda _: fake.unique.user_name())
    real_name = factory.LazyAttribute(lambda _: fake.name())
    avatar = factory.LazyAttribute(lambda _: fake.image_url())
    bio = factory.LazyAttribute(lambda _: fake.sentence(nb_words=10))
    is_email_verified = factory.LazyAttribute(
        lambda _: fake.boolean(chance_of_getting_true=75)
    )
    created_at = factory.LazyFunction(fake.date_time_this_year)
    updated_at = factory.LazyFunction(fake.date_time_this_year)
    is_active = True
    is_staff = False
    password = factory.PostGenerationMethodCall("set_password", "test1234")
