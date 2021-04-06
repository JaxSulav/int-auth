from django.conf import settings
from django.core.cache import cache
from django.core.cache.backends.base import DEFAULT_TIMEOUT

from provider.models import get_access_token_model
from .models import ViewGroupPermission

AccessToken = get_access_token_model()
CACHE_TTL = getattr(settings, 'CACHE_TTL', DEFAULT_TIMEOUT)


def cache_user_permissions(token, user):
    try:
        token = AccessToken.objects.get(token=token)
    except AccessToken.DoesNotExist:
        return False
    if token.is_expired():
        return False
    groups = user.groups.all()
    permissions = ViewGroupPermission.objects.filter(group__in=groups)
    permission_json = [permission.to_dict() for permission in permissions]
    cache.set(token, permission_json, timeout=CACHE_TTL)
    return permission_json


def get_user_permissions(token):
    """
    Method to fetch the permissions of a user token on views from cache.
    If no record for the provided token exists in cache, fetch it from database and store it in cache.

    We assume that the views calling this method is protected against expired or unauthorized tokens.
    :param token: AccessToken token string
    """
    permissions = cache.get(token, None)
    if not permissions:
        # get the permissions from database
        try:
            token_obj = AccessToken.objects.get(token=token)
        except AccessToken.DoesNotExist:
            return None
        if token_obj and not token_obj.is_expired():
            user = token_obj.user
            permissions = cache_user_permissions(token, user)
            return permissions
        else:
            return None
    return permissions


def map_view_name(view_path):
    pass
