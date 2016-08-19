from django.db import models

# Users are linked to a registration.
from django.contrib.auth.models import User


class Registration(models.Model):
    user = models.ForeignKey(User)
    email = models.EmailField(blank=True, null=True, verbose_name="Registration Email")
    institution = models.CharField(max_length=255, blank=True, null=True, verbose_name="Institution")

