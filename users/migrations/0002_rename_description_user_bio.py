# Generated by Django 5.2.2 on 2025-06-15 00:41

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0001_initial"),
    ]

    operations = [
        migrations.RenameField(
            model_name="user",
            old_name="description",
            new_name="bio",
        ),
    ]
