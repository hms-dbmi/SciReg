import jwt
import base64

from django.contrib.auth.models import User
from django.contrib import auth as django_auth
from django.contrib.auth import login
from django.conf import settings
from django.shortcuts import redirect

from stronghold.decorators import public

from django.contrib.auth import get_user_model
from django.utils.translation import ugettext as _
from rest_framework import exceptions
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.settings import api_settings


@public
def jwt_login(request):
    """
    Log a user in via a JWT token.
    :param request:
    :return:
    """
    # If not logged in, check for cookie with JWT.
    if not request.user.is_authenticated():
        try:
            jwt_string = request.COOKIES.get("DBMI_JWT", None)

            payload = jwt.decode(jwt_string, base64.b64decode(settings.AUTH0_SECRET, '-_'), algorithms=['HS256'],
                                 audience=settings.AUTH0_CLIENT_ID)
            request.session['profile'] = payload
            user = django_auth.authenticate(**payload)
            if user:
                login(request, user)
            else:
                print("Could not log user in.")
        except jwt.InvalidTokenError:
            print("No/Bad JWT Token.")

    if request.user.is_authenticated():
        redirect_url = request.GET.get("next", settings.AUTH0_SUCCESS_URL)

        return redirect(redirect_url)
    else:
        return redirect(settings.ACCOUNT_SERVER_URL + "?next=" + settings.AUTH0_SUCCESS_URL)


class Auth0Authentication(object):
    def authenticate(self, **token_dictionary):
        """
        Override authentication mechanism to use e-mail address as username.
        :param token_dictionary:
        :return:
        """
        print("Attempting to Authenticate User - " + token_dictionary["email"])

        try:
            user = User.objects.get(username=token_dictionary["email"])
        except User.DoesNotExist:
            print("User not found, creating.")

            user = User(username=token_dictionary["email"], email=token_dictionary["email"])
            user.save()
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER


class Auth0JSONWebTokenAuthentication(JSONWebTokenAuthentication):

    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id and email.
        """
        User = get_user_model()
        username = jwt_get_username_from_payload(payload)

        if not username:
            msg = _('Invalid payload.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            user = User.objects.get_by_natural_key(username)
        except User.DoesNotExist:
            print("User not found, creating.")

            user = User(username=username, email=username)
            user.save()

        if not user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.AuthenticationFailed(msg)

        return user
