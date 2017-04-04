import jwt
import base64

from django.contrib.auth.models import User
from django.contrib import auth as django_auth
from django.contrib.auth import login, logout
from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext as _
from rest_framework import exceptions
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.settings import api_settings

import logging
logger = logging.getLogger(__name__)


def user_auth_and_jwt(function):
    def wrap(request, *args, **kwargs):

        # User is both logged into this app and via JWT.
        if request.user.is_authenticated() and request.COOKIES.get("DBMI_JWT", None) is not None:
            return function(request, *args, **kwargs)
        # User has a JWT session open but not a Django session. Start a Django session and continue the request.
        elif not request.user.is_authenticated() and request.COOKIES.get("DBMI_JWT", None) is not None:
            jwt_login(request)
            return function(request, *args, **kwargs)
        # User doesn't pass muster, throw them to the login app.
        else:
            logout(request)
            response = redirect(settings.LOGIN_URL)
            response.delete_cookie('DBMI_JWT', domain=settings.COOKIE_DOMAIN)
            return response
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap


def jwt_login(request):
    """
    Log a user in via a JWT token.
    :param request:
    :return:
    """

    logger.debug("[SCIREG][DEBUG][jwt_login] - Logging user in via JWT. Is Authenticated? " + str(request.user.is_authenticated()))

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
        logger.debug("[SCIREG][DEBUG][Auth0Authentication] - Looking for user record." + token_dictionary["email"])

        try:
            user = User.objects.get(username=token_dictionary["email"])
        except User.DoesNotExist:
            logger.debug("[SCIREG][DEBUG][authenticate] - User not found, creating. ")

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
