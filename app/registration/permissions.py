from pyauth0jwt.auth0authenticate import validate_rs256_jwt, logout_redirect
from rest_framework import permissions, authentication, exceptions, status

import logging
logger = logging.getLogger(__name__)


def get_jwt(request):
    # Get the JWT token depending on request type
    if request.COOKIES.get('DBMI_JWT'):
        return request.COOKIES.get('DBMI_JWT')

    elif request.META.get('HTTP_AUTHORIZATION') and 'JWT ' in request.META.get('HTTP_AUTHORIZATION'):
        return request.META.get('HTTP_AUTHORIZATION').replace('JWT ', '')

    return None


def get_payload(request):
    # Get the JWT token depending on request type
    token = get_jwt(request)

    # Get the payload email
    return validate_rs256_jwt(token)


def get_email(request):

    # Get the payload email
    return get_payload(request).get('email')


def dbmi_user(view):
    '''
    Decorator to only check if the current user's JWT is valid
    '''
    def wrap(request, *args, **kwargs):

        # Get the token
        token = get_jwt(request)
        if not token:
            return logout_redirect(request)

        # User has a valid JWT from SciAuth
        if validate_rs256_jwt(token):

            return view(request, *args, **kwargs)

        else:
            return logout_redirect(request)

    return wrap


class DBMIAuthentication(authentication.BaseAuthentication):
    """
    Authentication method for DBMI API methods
    """

    def authenticate(self, request):

        # Get the JWT
        token = get_jwt(request)
        if not token:
            raise exceptions.NotAuthenticated

        # User has a valid JWT from SciAuth
        payload = validate_rs256_jwt(token)
        if not payload:
            raise exceptions.AuthenticationFailed

        # Return the user's email to attach to the request object (request.user)
        return payload.get('email'), token


class IsAuthenticated(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """

    def has_object_permission(self, request, view, obj):

        # Get the JWT
        token = get_jwt(request)
        if not token:
            raise exceptions.PermissionDenied

        # User has a valid JWT from SciAuth
        payload = validate_rs256_jwt(token)
        if not payload:
            raise exceptions.PermissionDenied

        return True


class IsAssociatedUser(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """

    def has_object_permission(self, request, view, obj):

        # Ensure emails match
        if obj.email == request.user:
            return True

        raise exceptions.PermissionDenied

