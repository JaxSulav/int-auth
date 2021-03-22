import logging
from datetime import timedelta

from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.utils import timezone

from .access_token import AccessToken, get_access_token_model
from .application import Application, get_application_model
from .id_token import IDToken, get_id_token_model
from .refresh_token import RefreshToken, get_refresh_token_model
from main.settings import auth_settings

logger = logging.getLogger(__name__)


def clear_expired():
    now = timezone.now()
    refresh_expire_at = None
    access_token_model = get_access_token_model()
    refresh_token_model = get_refresh_token_model()
    REFRESH_TOKEN_EXPIRE_SECONDS = auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS
    if REFRESH_TOKEN_EXPIRE_SECONDS:
        if not isinstance(REFRESH_TOKEN_EXPIRE_SECONDS, timedelta):
            try:
                REFRESH_TOKEN_EXPIRE_SECONDS = timedelta(seconds=REFRESH_TOKEN_EXPIRE_SECONDS)
            except TypeError:
                e = "REFRESH_TOKEN_EXPIRE_SECONDS must be either a timedelta or seconds"
                raise ImproperlyConfigured(e)
        refresh_expire_at = now - REFRESH_TOKEN_EXPIRE_SECONDS

    with transaction.atomic():
        if refresh_expire_at:
            revoked = refresh_token_model.objects.filter(
                revoked__lt=refresh_expire_at,
            )
            expired = refresh_token_model.objects.filter(
                access_token__expired__lt=refresh_expire_at,
            )
            logger.info("%s Revoked refresh tokens to be deleted", revoked.count())
            logger.info("%s Expired refresh tokens to be deleted", expired.count())

            revoked.delete()
            expired.delete()
        else:
            logger.info("refresh_expire_at is %s. No refresh tokens deleted.", refresh_expire_at)

        access_tokens = access_token_model.objects.filter(refresh_token__isnull=True, expires__lt=now)
        logger.info("%s Expired access tokens to be deleted", access_tokens.count())

        access_tokens.delete()
