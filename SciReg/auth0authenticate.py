from django.contrib.auth.models import User
from django.contrib import auth as django_auth
from django.contrib.auth import login
from django.conf import settings
from django.shortcuts import render, redirect

import jwt
import base64
import logging

from stronghold.decorators import public

logger = logging.getLogger(__name__)


@public
def jwt_login(request):
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
                logger.error("Could not log user in.")
        except jwt.InvalidTokenError:
            logger.error("No/Bad JWT Token.")

    if request.user.is_authenticated():
        redirect_url = request.GET.get("next", settings.AUTH0_SUCCESS_URL)

        return redirect(redirect_url)
    else:
        return redirect(settings.ACCOUNT_SERVER_URL + "?next=http://" + settings.AUTH0_SUCCESS_URL)


class Auth0Authentication(object):

    def authenticate(self, **token_dictionary):
        logger.debug("Attempting to Authenticate User - " + token_dictionary["email"])

        try:
            user = User.objects.get(username=token_dictionary["email"])
        except User.DoesNotExist:
            logger.debug("User not found, creating.")

            user = User(username=token_dictionary["email"], email=token_dictionary["email"])
            user.is_staff = True
            user.is_superuser = True
            user.save()
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


