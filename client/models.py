from django.db import models

# Create your models here.


class Settings(models.Model):
    name = models.CharField(blank=False, null=False, primary_key=True, max_length=255)
    value = models.TextField(blank=False, null=False)

    def __str__(self) -> str:
        return self.name


class X509(models.Model):
    name = models.CharField(blank=False, null=False, unique=True, max_length=255)
    crt = models.TextField(blank=False, null=False)
    key = models.TextField(blank=False, null=False)

    def __str__(self) -> str:
        return self.name
