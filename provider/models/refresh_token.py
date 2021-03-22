from django.apps import apps
from django.conf import settings
from django.db import models, transaction
from django.utils import timezone

from main.settings import auth_settings
from .access_token import get_access_token_model


class RefreshToken(models.Model):
    """
    A RefreshToken instance represents a token that can be swapped for a new access token
    when it expires.

    Fields:
    * :attr:`user` The Django user representing resource owner
    * :attr:`token` Token value
    * :attr:`application` Application instance
    * :attr:`access_token` AccessToken instance this refresh token is bounded to
    * :attr:`revoked` Timestamp of when this refresh token was revoked
    """

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="refresh_tokens", on_delete=models.CASCADE)
    token = models.CharField(max_length=255)
    application = models.ForeignKey(auth_settings.APPLICATION_MODEL, on_delete=models.CASCADE)
    access_token = models.OneToOneField(
        auth_settings.ACCESS_TOKEN_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="refresh_token")
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    revoked = models.DateTimeField(null=True)

    def revoke(self):
        """
        Mark this refresh token revoked and revoke related access token
        """
        access_token_model = get_access_token_model()
        refresh_token_model = get_refresh_token_model()
        with transaction.atomic():
            token = refresh_token_model.objects.select_for_update().filter(pk=self.pk, revoked__isnull=True)
            if not token:
                return
            self = list(token)[0]

            try:
                access_token_model.objects.get(id=self.access_token_id).revoke()
            except access_token_model.DoesNotExist:
                pass
            self.access_token = None
            self.revoked = timezone.now()
            self.save()

    def __str__(self):
        return self.token

    class Meta:
        unique_together = ("token", "revoked")


def get_refresh_token_model():
    """Return RefreshToken instance that is active in this project"""
    return apps.get_model(auth_settings.REFRESH_TOKEN_MODEL)
