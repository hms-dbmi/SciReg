import mock
import re

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.core import mail
from rest_framework.test import APIClient
from socket import gaierror

from .views import email_confirm


class TestUser:
    fhir_id = '1001'
    first_name = 'Test'
    last_name = 'User'
    email = 'testuser@email.com'
    phone = '555-555-5555'
    address = '5555 Broadway Blvd.'
    city = 'Boston'
    zip = '02148'
    state = 'MA'
    password = 'testpassword'
    token = 'WIUHDI&WHQDBKbIYWGD^GUQG^DG&wdydwg^@@Ejdh37364BQWKDBKWDU##B@@9wUDBi&@GiYWBD'
    twitter = 'testuser'

email = "TEST@TEST.COM"
username = "TEST@TEST.COM"
password = "TESTPASS"

user_profile = {"email": email,
                  "affiliation": "",
                  "affiliation_type": "",
                  "data_interest": "",
                  "software_interest": "",
                  "technical_consult_interest": ""}


@mock.patch('pyauth0jwt.auth0authenticate.validate_jwt', lambda x: TestUser.token)
class RegistrationTestCase(TestCase):

    def setUp(self):

        # Create a client.
        self.client = Client()

        # Create a user.
        self.user = get_user_model().objects.create(email=TestUser.email, username=TestUser.email)
        self.user.save()

        # Log them in.
        self.client.cookies['DBMI_JWT'] = TestUser.token
        self.client.force_login(self.user, backend='django.contrib.auth.backends.ModelBackend')

    def test_register_page(self):
        """
        Testing methods related to creating a user.
        :return:
        """

        # Try to create a profile for a user.
        response = self.client.post("/registration/profile/", user_profile)
        self.assertEqual(response.status_code, 200)


@mock.patch('pyauth0jwt.auth0authenticate.validate_jwt', lambda x: TestUser.token)
class EmailVerificationTestCase(TestCase):

    def setUp(self):

        # Create a client.
        self.client = Client()

        # Create a user.
        self.user = get_user_model().objects.create(email=TestUser.email, username=TestUser.email)
        self.user.save()

        # Log them in.
        self.client.cookies['DBMI_JWT'] = TestUser.token
        self.client.force_login(self.user, backend='django.contrib.auth.backends.ModelBackend')

        # Create the api client.
        self.api_client = APIClient()
        self.api_client.force_authenticate(self.user, TestUser.token)

    def test_email_confirm_unauthorized(self):

        # Set the return URL.
        success_url = 'http://localhost:8010/dashboard/dashboard/'

        # Get the email confirm email.
        api_client = APIClient()
        response = api_client.post('/api/register/send_confirmation_email/',
                                   data={'success_url': success_url},
                                   follow=True)

        # Ensure the email was not sent.
        self.assertEqual(response.status_code, 401, msg='Response did not return 401 for unauthorized access')
        self.assertEqual(len(mail.outbox), 0, msg='Email confirmation email was sent despite unauthorized access')

    def test_email_confirm_code(self):

        # Set the return URL.
        success_url = 'http://localhost:8010/dashboard/dashboard/'

        # Get the email confirm email.
        response = self.api_client.post('/api/register/send_confirmation_email/',
                                        data={'success_url': success_url})

        # Ensure the email sent.
        self.assertEqual(response.status_code, 200, msg='Response did not return 200 after sending email')
        self.assertEqual(len(mail.outbox), 1, msg='Email confirmation email was not sent')

        # Get the code.
        code = re.search('email_confirm_value\=([^&\s]+)', mail.outbox[0].body).group(1)

        # Ensure it exists.
        self.assertIsNotNone(code, msg='No email confirmation code was included in the email')

    def test_email_confirm_success_url(self):

        # Set the return URL.
        success_url = 'http://localhost:8010/dashboard/dashboard/'

        # Get the email confirm email.
        response = self.api_client.post('/api/register/send_confirmation_email/',
                                        data={'success_url': success_url})

        # Ensure the email sent.
        self.assertEqual(response.status_code, 200, msg='Response did not return 200 after sending email')
        self.assertEqual(len(mail.outbox), 1, msg='Email confirmation email was not sent')

        # Get the code.
        success_url = re.search('success_url\=([^&\s]+)', mail.outbox[0].body).group(1)

        # Ensure it exists.
        self.assertIsNotNone(success_url, msg='No success URL was included in the email')

    def test_email_confirm_success_contents(self):

        # Set the return URL.
        success_url = 'http://localhost:8010/dashboard/dashboard/'

        # Get the email confirm email.
        response = self.api_client.post('/api/register/send_confirmation_email/',
                                        data={'success_url': success_url})

        # Ensure the email sent.
        self.assertEqual(response.status_code, 200, msg='Response did not return 200 after sending email')
        self.assertEqual(len(mail.outbox), 1, msg='Email confirmation email was not sent')

        # Get the code.
        code = re.search('email_confirm_value\=([^&\s]+)', mail.outbox[0].body).group(1)

        # Ensure it exists.
        self.assertIsNotNone(code, msg='No email confirmation code was included in the email')

        # Get the code.
        success_url = re.search('success_url\=([^&\s]+)', mail.outbox[0].body).group(1)

        # Ensure it exists.
        self.assertIsNotNone(success_url, msg='No success URL was included in the email')

    def test_email_confirm_success(self):

        # Set the return URL.
        success_url = 'http://localhost:8010/dashboard/dashboard/'

        # Get the email confirm email.
        response = self.api_client.post('/api/register/send_confirmation_email/',
                                        data={'success_url': success_url})

        # Ensure the email sent.
        self.assertEqual(response.status_code, 200, msg='Response did not return 200 after sending email')
        self.assertEqual(len(mail.outbox), 1, msg='Email confirmation email was not sent')

        # Get the code.
        code = re.search('email_confirm_value\=([^&\s]+)', mail.outbox[0].body).group(1)

        # Make the request.
        response = self.client.get(reverse(email_confirm),
                                   data={'email_confirm_value': code})

        # Ensure it succeeded.
        self.assertEqual(response.status_code, 200)

        # Check for a message.
        messages = list(response.wsgi_request._messages)
        self.assertNotEqual(len(messages), 0,
                            msg='No messages have been saved despite an error occurring during the process')
        self.assertIn('Email has been confirmed', str(messages[0]),
                      msg='The message text did not match the expected success message')

        # Check for an error.
        self.assertContains(response, 'Email has been confirmed',
                      msg_prefix='The response content text did not match the expected success message')

    def test_email_confirm_success_redirect(self):

        # Set the return URL.
        success_url = 'http://localhost:8010/dashboard/dashboard/'

        # Get the email confirm email.
        response = self.api_client.post('/api/register/send_confirmation_email/',
                                        data={'success_url': success_url})

        # Ensure the email sent.
        self.assertEqual(response.status_code, 200, msg='Response did not return 200 after sending email')
        self.assertEqual(len(mail.outbox), 1, msg='Email confirmation email was not sent')

        # Get the code.
        code = re.search('email_confirm_value\=([^&\s]+)', mail.outbox[0].body).group(1)

        # Make the request.
        response = self.client.get(reverse(email_confirm),
                                   data={'email_confirm_value': code,
                                         'success_url': success_url},
                                   follow=True)

        # Ensure it succeeded.
        self.assertRedirects(response, status_code=302, target_status_code=404, expected_url=success_url)

        # Check for a message.
        messages = list(response.wsgi_request._messages)
        self.assertNotEqual(len(messages), 0,
                            msg='No messages have been saved despite an error occurring during the process')
        self.assertIn('Email has been confirmed', str(messages[0]),
                      msg='The message text did not match the expected success message')

    def test_email_confirm_failure(self):

        # Set the return URL.
        success_url = 'http://localhost:8010/dashboard/dashboard/'

        # Get the email confirm email.
        response = self.api_client.post('/api/register/send_confirmation_email/',
                                        data={'success_url': success_url})

        # Ensure the email sent.
        self.assertEqual(response.status_code, 200, 'Response did not return 200 after sending email')
        self.assertEqual(len(mail.outbox), 1, 'Email confirmation email was not sent')

        # Get the code.
        code = re.search('email_confirm_value\=([^&\s]+)', mail.outbox[0].body).group(1)

        # Change a character.
        code = code[:len(code) - 1]

        # Make the request.
        response = self.client.get(reverse(email_confirm),
                                   data={'email_confirm_value': code})

        # Ensure it succeeded.
        self.assertEqual(response.status_code, 200,
                         msg='Response did not return 200 after processing email verification')

        # Check for a message.
        messages = list(response.wsgi_request._messages)
        self.assertNotEqual(len(messages), 0,
                            msg='No messages have been saved despite an error occurring during the process')
        self.assertIn('This email confirmation code is invalid', str(messages[0]),
                      msg='The message text did not match the expected error message')

        # Check for an error.
        self.assertContains(response, 'This email confirmation code is invalid')

    def test_email_confirm_empty(self):

        # Make the request.
        response = self.client.get(reverse(email_confirm))

        # Ensure it returns a valid response.
        self.assertEqual(response.status_code, 200,
                         msg='Response did not return 200 after processing email verification')

        # Check for a message.
        messages = list(response.wsgi_request._messages)
        self.assertNotEqual(len(messages), 0,
                            msg='No messages have been saved despite an error occurring during the process')
        self.assertIn('This email confirmation code is invalid', str(messages[0]),
                      msg='The message text did not match the expected error message')

        # Check for an error.
        self.assertContains(response, 'This email confirmation code is invalid',
                      msg_prefix='The response content text did not match the expected error message')

    def test_email_confirm_invalid(self):

        # Make the request.
        response = self.client.get(reverse(email_confirm),
                                   data={'email_confirmation_code': 'qhdiq38hiuewfhbiu3gf98bgisujbfiwu3fw'})

        # Ensure it returns a valid response.
        self.assertEqual(response.status_code, 200,
                         msg='Response did not return 200 after processing email verification')

        # Check for a message.
        messages = list(response.wsgi_request._messages)
        self.assertNotEqual(len(messages), 0,
                            msg='No messages have been saved despite an error occurring during the process')
        self.assertIn('This email confirmation code is invalid', str(messages[0]),
                      msg='The message text did not match the expected error message')

        # Check for an error.
        self.assertContains(response, 'This email confirmation code is invalid',
                      msg_prefix='The response content text did not match the expected error message')

    def test_email_confirm_invalid_redirect(self):

        # Set the parameters.
        data = {
            'email_verification_code': 'qhdiq38hiuewfhbiu3gf98bgisujbfiwu3fw',
            'success_url': 'http://www.google.com',
        }

        # Make the request.
        response = self.client.get(reverse(email_confirm), data=data)

        # Ensure it redirected.
        self.assertRedirects(response, status_code=302, target_status_code=200, expected_url=data['success_url'])

        # Check for a message.
        messages = list(response.wsgi_request._messages)
        self.assertNotEqual(len(messages), 0,
                            msg='No messages have been saved despite an error occurring during the process')
        self.assertIn('This email confirmation code is invalid', str(messages[0]),
                      msg='The message text did not match the expected error message')

    @mock.patch('registration.views.EmailMultiAlternatives.send', new=mock.Mock(side_effect=gaierror('ERROR')))
    def test_email_send_error(self):

        # Set the return URL.
        success_url = 'http://localhost:8010/dashboard/dashboard/'

        # Get the email confirm email.
        response = self.api_client.post('/api/register/send_confirmation_email/',
                                        data={'success_url': success_url})

        # Check response content.
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('SENT', str(response.content),
                         msg='Response indicates the email was sent despite an error being thrown')

        # Ensure the email was not sent.
        self.assertEqual(len(mail.outbox), 0, msg='An email was sent despite an error being thrown')
