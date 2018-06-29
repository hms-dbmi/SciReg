from rest_framework import serializers
from registration.models import Registration
from django.contrib.auth.models import User
from django_countries.serializers import CountryFieldMixin

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email', 'username')


class RegistrationSerializer(CountryFieldMixin, serializers.ModelSerializer):
    last_updated = serializers.DateTimeField(format="%Y-%m-%d", required=False, read_only=True)

    class Meta:
        model = Registration
        fields = ('id',
                  'email',
                  'first_name',
                  'last_name',
                  'street_address1',
                  'street_address2',
                  'city',
                  'state',
                  'zipcode',
                  'country',
                  'phone_number',
                  'twitter_handle',
                  'email_confirmed',
                  'professional_title',
                  'affiliation_type',
                  'institution',
                  'alternate_email',
                  'last_updated')
