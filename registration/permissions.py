from rest_framework import permissions


class IsAssociatedUser(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """

    def has_object_permission(self, request, view, obj):
        return obj.user == request.user


def jwt_get_username_from_payload(payload):
    return payload.get('email')