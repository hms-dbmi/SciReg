from rest_framework import serializers
from registration.models import Registration


class RegistrationSerializer(serializers.ModelSerializer):

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
                  'phone_number',
                  'twitter_handle')
