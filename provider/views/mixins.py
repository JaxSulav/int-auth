from django.http import HttpResponse, HttpResponseForbidden, JsonResponse

from main.settings import auth_settings
from provider.exceptions import FatalClientError


class OAuthMixin:
    server_class = None
    validator_class = None
    oauthlib_backend_class = None

    @classmethod
    def get_server_class(cls):
        """
        Return the OAuthlib server class to use
        """
        if cls.server_class is None:
            return auth_settings.OAUTH2_SERVER_CLASS
        else:
            return cls.server_class

    @classmethod
    def get_validator_class(cls):
        if cls.validator_class is None:
            return auth_settings.OAUTH2_VALIDATOR_CLASS
        else:
            return cls.validator_class

    @classmethod
    def get_oauthlib_backend_class(cls):
        """
        Return the OAuthlib backend class
        """
        if cls.oauthlib_backend_class is None:
            return auth_settings.OAUTH2_BACKEND_CLASS
        else:
            return cls.oauthlib_backend_class

    @classmethod
    def get_server(cls):
        """
        Return the instance of `server_class` initialized with validator
        """
        server_class = cls.get_server_class()
        validator_class = cls.get_validator_class()
        server_kwargs = auth_settings.server_kwargs
        return server_class(validator_class(), **server_kwargs)

    @classmethod
    def get_oauthlib_core(cls):
        if not hasattr(cls, "_oauthlib_core"):
            server = cls.get_server()
            core_class = cls.get_oauthlib_backend_class()
            cls._oauthlib_core = core_class(server)
        return cls._oauthlib_core

    def validate_authorization_request(self, request):
        """
        A wrapper method that calls `validate_authentication_request` on `server_class` instance.
        :param request: The current django.HttpRequest object
        """
        core = self.get_oauthlib_core()
        return core.validate_authorization_request(request)

    def create_authorization_response(self, request, scopes, credentials, allow):
        """
        A wrapper method that calls create_authorization_response on `server_class`
        instance.
        :param request: The current django.http.HttpRequest object
        :param scopes: A space-separated string of provided scopes
        :param credentials: Authorization credentials dictionary containing
                           `client_id`, `state`, `redirect_uri` and `response_type`
        :param allow: True if the user authorize the client, otherwise False
        """
        # TODO: move this scopes conversion from and to string into a utils function
        scopes = scopes.split(" ") if scopes else []

        core = self.get_oauthlib_core()
        return core.create_authorization_response(request, scopes, credentials, allow)

    def create_token_response(self, request):
        """
        A wrapper method that calls create_token_response on `server_class` instance.
        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()
        return core.create_token_response(request)

    def create_revocation_response(self, request):
        """
        A wrapper method that calls create_revocation_response on the
        `server_class` instance.
        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()
        return core.create_revocation_response(request)

    def create_userinfo_response(self, request):
        """
        A wrapper method that calls create_userinfo_response on the
        `server_class` instance.
        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()
        return core.create_userinfo_response(request)

    def verify_request(self, request):
        """
        A wrapper method that calls verify_request on `server_class` instance.
        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()
        return core.verify_request(request, scopes=self.get_scopes())

    def get_scopes(self):
        """
        This should return the list of scopes required to access the resources.
        By default it returns an empty list.
        """
        return []

    def error_response(self, error, **kwargs):
        """
        Return an error to be displayed to the resource owner if anything goes awry.
        :param error: :attr:`OAuthToolkitError`
        """
        oauthlib_error = error.oauthlib_error

        redirect_uri = oauthlib_error.redirect_uri or ""
        separator = "&" if "?" in redirect_uri else "?"

        error_response = {
            "error": oauthlib_error,
            "url": redirect_uri + separator + oauthlib_error.urlencoded,
        }
        error_response.update(kwargs)

        # If we got a malicious redirect_uri or client_id, we will *not* redirect back to the URL.
        if isinstance(error, FatalClientError):
            redirect = False
        else:
            redirect = True

        return redirect, error_response

    def authenticate_client(self, request):
        """Returns a boolean representing if client is authenticated with client credentials
        method. Returns `True` if authenticated.
        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()
        return core.authenticate_client(request)


class ProtectedResourceMixin(OAuthMixin):
    """
    Helper mixin that implements OAuth2 protection on request dispatch,
    specially useful for Django Generic Views.

    To validate, we need to pass the token obtained after successful user login in the header as:
        {'Authorization': 'Bearer <access_token>'}
    """

    def dispatch(self, request, *args, **kwargs):
        # let preflight OPTIONS requests pass
        if request.method.upper() == "OPTIONS":
            return super().dispatch(request, *args, **kwargs)

        # check if the request is valid and the protected resource may be accessed
        valid, r = self.verify_request(request)
        if valid:
            return super().dispatch(request, *args, **kwargs)
        else:
            error = r.oauth2_error
            return JsonResponse(error)
