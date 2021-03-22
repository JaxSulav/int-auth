import base64
import binascii
import logging
import uuid
from urllib.parse import unquote_plus

from django.conf import settings
from django.contrib.auth import get_user_model
from oauthlib.openid import RequestValidator

from .models import (
    get_access_token_model,
    get_application_model,
    get_id_token_model,
    get_refresh_token_model
)
from main.settings import auth_settings

log = logging.getLogger(__name__)

Application = get_application_model()
AccessToken = get_access_token_model()
IDToken = get_id_token_model()
RefreshToken = get_refresh_token_model()
User = get_user_model()

GRANT_TYPE_MAPPING = {
    "authorization_code": (
        Application.GRANT_AUTHORIZATION_CODE  # we will just be using authorization code
    ),
    "refresh_token": (
        Application.GRANT_AUTHORIZATION_CODE
    )
}


class AuthValidator(RequestValidator):
    def _extract_basic_auth(self, request):
        """
        Return authentication string if request contains basic auth credentials, else None
        """
        auth = request.headers.get("HTTP_AUTHORIZATION", None)
        if not auth:
            return None
        splitted = auth.split(" ", 1)
        if len(splitted) != 2:
            return None
        auth_type, auth_string = splitted

        if auth_type != "Basic":
            return None

        return auth_string

    def _authenticate_basic_auth(self, request):
        """
        Authenticates with basic HTTP auth
        Note: as stated in rfc:`2.3.1`, client_id and client_secret must be encoded with
        "application/x-www-form-urlencoded" encoding algorithm.
        """
        auth_string = self._extract_basic_auth(request)
        if not auth_string:
            return False

        try:
            encoding = request.encoding or settings.DEFAULT_CHARSET or "utf-8"
        except AttributeError:
            encoding = "utf-8"

        try:
            b64_decoded = base64.b64decode(auth_string)
        except (TypeError, binascii.Error):
            log.debug("Failed basic auth: %r can't be decoded as base64", auth_string)
            return False

        try:
            auth_string_decoded = b64_decoded.decode(encoding)
        except UnicodeDecodeError:
            log.debug("Failed basic auth: %r can't be decoded as unicode by %r", auth_string, encoding)
            return False

        try:
            client_id, client_secret = map(unquote_plus, auth_string_decoded.split(":", 1))
        except ValueError:
            log.debug("Failed basic auth, Invalid base64 encoding.")
            return False

        if self._load_application(client_id, request) is None:
            log.debug("Failed basic auth: Application %s does not exist."% client_id)
            return False
        elif request.client.client_id != client_id:
            log.debug("Failed basic auth: wrong client id %s"% client_id)
            return False
        elif request.client.client_secret != client_secret:
            log.debug("Failed basic auth: wrong client secret %s"% client_secret)
            return False
        else:
            return True

    def _authenticate_request_body(self, request):
        """
        Try to authenticate the client using client_id and client_secret
        parameters included in body
        Remember that this method is NOT RECOMMENDED and SHOULD be limited to
        clients unable to directly utilize the HTTP Basic authentication scheme.
        See rfc:`2.3.1` for more details.
        """
        try:
            client_id = request.client_id
            client_secret = request.client_secret
        except AttributeError:
            return False

        if self._load_application(client_id, request) is None:
            log.debug("Failed body auth: Application %s does not exists" % client_id)
            return False
        elif request.client.client_secret != client_secret:
            log.debug("Failed body auth: wrong client secret %s" % client_secret)
            return False
        else:
            return True

    def _load_application(self, client_id, request):
        """
        If request.client was not set, load application instance for given
        client_id and store it in request.client
        """

        # we want to be sure that request has the client attribute!
        assert hasattr(request, "client"), '"request" instance has no "client" attribute'

        try:
            request.client = request.client or Application.objects.get(client_id=client_id)
            # Check that the application can be used (defaults to always True)
            if not request.client.is_usable(request):
                log.debug("Failed body authentication: Application %r is disabled" % client_id)
                return None
            return request.client
        except Application.DoesNotExist:
            log.debug("Failed body authentication: Application %r does not exist" % client_id)
            return None
