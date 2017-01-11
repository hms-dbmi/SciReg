from django.contrib.auth.models import User
from django.contrib import auth as django_auth
from django.contrib.auth import login
from django.conf import settings
from django.shortcuts import redirect

import jwt
import base64

from stronghold.decorators import public


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
            user.is_staff = True
            user.is_superuser = True
            user.save()
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


