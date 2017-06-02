from rest_framework import permissions
from django.contrib.auth.models import User


class IsAssociatedUser(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """

    def has_object_permission(self, request, view, obj):
        return obj.user == request.user


def jwt_get_username_from_payload(payload):
    """
    Method to create user in SciReg Application if they don't exist.
    """

    print("[SCIREG][DEBUG][jwt_get_username_from_payload] - Attempting to Authenticate User - " + payload.get('email'))

    try:
        User.objects.get(username=payload.get('email'))
    except User.DoesNotExist:

        print("[SCIREG][DEBUG][jwt_get_username_from_payload] - User not found, creating.")

        user = User(username=payload.get('email'), email=payload.get('email'))
        user.save()

    return payload.get('email')
