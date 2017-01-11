from django.db import models

# Users are linked to a registration.
from django.contrib.auth.models import User


class Registration(models.Model):
    """
    This is a model of a user's registration.
    """

    ACADEMIC = 'AC'
    INDUSTRY = 'IN'

    AFFILIATION_CHOICES = (
        (ACADEMIC, 'Academic'),
        (INDUSTRY, 'Industry')
    )

    user = models.ForeignKey(User)
    email = models.EmailField(blank=True, null=True, verbose_name="Registration Email")
    first_name = models.CharField(max_length=255, blank=True, null=True, verbose_name="First Name")
    last_name = models.CharField(max_length=255, blank=True, null=True, verbose_name="Last Name")

    street_address1 = models.CharField(max_length=255, blank=True, null=True, verbose_name="Street Address 1")
    street_address2 = models.CharField(max_length=255, blank=True, null=True, verbose_name="Street Address 2")
    city = models.CharField(max_length=255, blank=True, null=True, verbose_name="City")
    state = models.CharField(max_length=255, blank=True, null=True, verbose_name="State")
    zipcode = models.CharField(max_length=255, blank=True, null=True, verbose_name="Zip")

    phone_number = models.CharField(max_length=255, blank=True, null=True, verbose_name="Phone Number")

    twitter_handle = models.CharField(max_length=255, blank=True, null=True, verbose_name="Twitter Handle")

    affiliation_type = models.CharField(max_length=20, blank=True, null=True, verbose_name="Affiliation Type", choices=AFFILIATION_CHOICES, default=ACADEMIC)
    affiliation = models.CharField(max_length=255, blank=True, null=True, verbose_name="Affiliation")
    software_interest = models.BooleanField(default=False)
    data_interest = models.BooleanField(default=False)
    technical_consult_interest = models.BooleanField(default=False)

    registered = models.BooleanField(default=False)
