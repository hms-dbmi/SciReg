from django.test import TestCase, Client
from django.contrib.auth import get_user_model

email = "TEST@TEST.COM"
username = "TEST@TEST.COM"
password = "TESTPASS"

user_profile = {"email": email,
                  "affiliation": "",
                  "affiliation_type": "",
                  "data_interest": "",
                  "software_interest": "",
                  "technical_consult_interest": ""}

class RegistrationTestCase(TestCase):
    def setup(self):
        get_user_model().objects.create_user(username, email=email, password=password)

    def test_register_page(self):
        """
        Testing methods related to creating a user.
        :return:
        """

        # Establish test client.
        test_client = Client()
        test_client.login(username=email, email=email, password=password)

        # Try to create a profile for a user.
        response = test_client.post("/registration/profile/", user_profile)
        self.assertEqual(response.status_code, 200)
