from django.db import models

# Users are linked to a registration.
from django.contrib.auth.models import User

class Registration(models.Model):
    ACADEMIC = 'AC'
    INDUSTRY = 'IN'

    AFFILIATION_CHOICES = (
        (ACADEMIC, 'Academic'),
        (INDUSTRY, 'Industry')
    )

    user = models.ForeignKey(User)
    email = models.EmailField(blank=True, null=True, verbose_name="Registration Email")
    affiliation_type = models.CharField(max_length=20, blank=True, null=True, verbose_name="Affiliation Type", choices=AFFILIATION_CHOICES, default=ACADEMIC)
    affiliation = models.CharField(max_length=255, blank=True, null=True, verbose_name="Affiliation")
    software_interest = models.BooleanField(default=False)
    data_interest = models.BooleanField(default=False)
    technical_consult_interest = models.BooleanField(default=False)

    registered = models.BooleanField(default=False)
