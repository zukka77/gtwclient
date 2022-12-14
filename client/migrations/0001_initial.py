# Generated by Django 4.0.6 on 2022-07-22 07:02

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Settings",
            fields=[
                ("name", models.CharField(max_length=255, primary_key=True, serialize=False)),
                ("value", models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name="X509",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=255, unique=True)),
                ("crt", models.TextField()),
                ("key", models.TextField()),
            ],
        ),
    ]
