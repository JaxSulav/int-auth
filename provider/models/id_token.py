import uuid

from django.apps import apps
from django.db import models
from django.utils import timezone

from main.settings import auth_settings


class IDToken(models.Model):
    """
    An IDToken instance represents the actual token to
    access user's resources, as in :openid:`2`.

    Fields:
    * :attr:`user_id` User id from user service
    * :attr:`jti` ID token JWT Token ID, to identify an individual token
    * :attr:`application` Application instance
    * :attr:`expires` Date and time of token expiration, in DateTime format
    * :attr:`scope` Allowed scopes
    * :attr:`created` Date and time of token creation, in DateTime format
    * :attr:`updated` Date and time of token update, in DateTime format
    """

    id = models.BigAutoField(primary_key=True)
    user_id = models.IntegerField(null=True, blank=True)
    jti = models.UUIDField(unique=True, default=uuid.uuid4, editable=False, verbose_name="JWT Token ID")
    application = models.ForeignKey(
        auth_settings.APPLICATION_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True
    )
    expires = models.DateTimeField()
    scope = models.TextField(blank=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def is_valid(self):
        """
        Checks if access token is valid
        """
        return not self.is_expired()

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def revoke(self):
        """
        Convenience method to uniform tokens' interface, for now
        simply remove this token from the database in order to revoke it.
        """
        self.delete()

    def __str__(self):
        return "JTI: {self.jti} User: {self.user_id}".format(self=self)


def get_id_token_model():
    """Return IDToken class active in this project"""
    return apps.get_model(auth_settings.ID_TOKEN_MODEL)
